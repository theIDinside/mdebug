#include "supervisor.h"
#include "bp.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "interface/dap/types.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "notify_pipe.h"
#include "ptrace.h"
#include "ptracestop_handlers.h"
#include "so_loading.h"
#include "symbolication/block.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/dwarf/name_index.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_expressions.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/elf.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tasks/lnp.h"
#include "tracer.h"
#include "utils/byte_buffer.h"
#include "utils/enumerator.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/logger.h"
#include "utils/worker_task.h"
#include <algorithm>
#include <chrono>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <link.h>
#include <memory_resource>
#include <optional>
#include <ratio>
#include <set>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <variant>

using sym::dw::SourceCodeFile;

TraceeController::TraceeController(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify,
                                   TargetSession target_session, bool seized, bool open_mem_fd) noexcept
    : task_leader{process_space_id}, main_executable{nullptr}, threads{}, task_vm_infos{}, pbps{*this},
      tracee_r_debug{nullptr}, shared_objects{}, stop_all_requested{false}, var_refs(), interpreter_base{},
      entry{}, session{target_session}, ptracestop_handler{new ptracestop::StopHandler{*this}},
      null_unwinder{new sym::Unwinder{nullptr}}, ptrace_session_seized{seized}
{
  threads.reserve(256);
  awaiter_thread = std::make_unique<AwaiterThread>(awaiter_notify, process_space_id);
  threads.push_back(TaskInfo::create_running(process_space_id));
  threads.back().initialize();
  if (open_mem_fd) {
    const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
    procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
  }

  new_objectfile.subscribe(SubscriberIdentity::Of(this), [](const SymbolFile *sf) {
    Tracer::Instance->post_event(new ui::dap::ModuleEvent{"new", *sf});
    return true;
  });
}

std::shared_ptr<SymbolFile>
TraceeController::lookup_symbol_file(const Path &path) noexcept
{
  for (const auto &s : symbol_files) {
    if (s->objectFile()->path == path)
      return s;
  }
  return nullptr;
}

bool
TraceeController::reopen_memfd() noexcept
{
  const auto procfs_path = fmt::format("/proc/{}/task/{}/mem", task_leader, task_leader);
  procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
  return procfs_memfd.is_open();
}

struct ProbeInfo
{
  AddrPtr address;
  std::string name;
};

static std::vector<ProbeInfo>
parse_stapsdt_note(const Elf *elf, const ElfSection *section) noexcept
{
  std::vector<ProbeInfo> probes;
  DwarfBinaryReader reader{elf, section};
  std::set<std::string_view> required_probes{{"map_complete", "reloc_complete", "unmap_complete"}};
  // stapsdt, location 8 bytes, base 8 bytes, semaphore 8 bytes, desc=string of N bytes, then more bytes we don't
  // care for

  while (reader.has_more() && required_probes.size() > 0) {
    reader.read_value<u32>();
    reader.read_value<u32>();
    reader.read_value<u32>();
    // const auto stapsdt = reader.read_string();
    // ASSERT(stapsdt == "stapsdt", "Failed to see 'stapsdt' deliminator; saw {}", stapsdt);
    // instead just skip:
    reader.skip_string();

    const auto ptr = reader.read_value<u64>();
    // base =
    reader.skip_value<u64>();
    // semaphore =
    reader.skip_value<u64>();

    // same here
    // const auto provider = reader.read_string();
    // ASSERT(provider == "rtld", "Supported provider is rtld, got {}", provider);
    reader.skip_string();
    const auto probe_name = reader.read_string();
    reader.skip_string();
    if (reader.bytes_read() % 4 != 0)
      reader.skip(4 - reader.bytes_read() % 4);
    if (required_probes.contains(probe_name)) {
      probes.push_back(ProbeInfo{.address = ptr, .name = std::string{probe_name}});
      required_probes.erase(std::find(required_probes.begin(), required_probes.end(), probe_name));
    }
  }
  return probes;
}

static TPtr<r_debug_extended>
get_rdebug_state(ObjectFile *obj_file)
{
  const auto rdebug_state = obj_file->get_min_obj_sym(LOADER_STATE);
  ASSERT(rdebug_state.has_value(), "Could not find _r_debug!");
  return rdebug_state->address.as<r_debug_extended>();
}

void
TraceeController::install_loader_breakpoints() noexcept
{
  ASSERT(interpreter_base.has_value(),
         "Haven't read interpreter base address, we will have no idea about where to install breakpoints");
  const auto mainExecutableElf = main_executable->objectFile()->elf;
  auto int_path = interpreter_path(mainExecutableElf, mainExecutableElf->get_section(".interp"));
  auto tmp_objfile = CreateObjectFile(*this, int_path);
  ASSERT(tmp_objfile != nullptr, "Failed to mmap the loader binary");
  const auto system_tap_sec = tmp_objfile->elf->get_section(".note.stapsdt");
  const auto probes = parse_stapsdt_note(tmp_objfile->elf, system_tap_sec);
  tracee_r_debug = interpreter_base.value() + get_rdebug_state(tmp_objfile.get());
  DLOG("mdb", "_r_debug found at {}", tracee_r_debug);
  for (const auto symbol_name : LOADER_SYMBOL_NAMES) {
    if (auto symbol = tmp_objfile->get_min_fn_sym(symbol_name); symbol) {
      const auto addr = interpreter_base.value() + symbol->address;
      DLOG("mdb", "Setting ld breakpoint at {}", addr);
      pbps.create_loc_user<SOLoadingBreakpoint>(*this, get_or_create_bp_location(addr, false), task_leader);
    }
  }
}

static auto
createNewOrCopyIfUniqueSymbolFile(auto &tc, auto path, AddrPtr addr) -> std::shared_ptr<SymbolFile>
{
  auto existing_obj = Tracer::Instance->LookupSymbolfile(path);
  if (existing_obj) {
    // if baseAddr == addr; unique = false, return null
    return existing_obj->baseAddress != addr ? existing_obj->copy(tc, addr) : nullptr;
  } else {
    auto obj = CreateObjectFile(tc, path);
    if (obj != nullptr) {
      return SymbolFile::Create(tc, obj, addr);
    }
  }
  return nullptr;
}

void
TraceeController::on_so_event() noexcept
{
  DLOG("mdb", "so event triggered");
  // tracee_r_debug: TPtr<r_debug> points to tracee memory where r_debug lives
  r_debug_extended rdebug_ext = read_type(tracee_r_debug);
  std::vector<std::shared_ptr<SymbolFile>> obj_files{};
  // TODO(simon): Make this asynchronous; so that instead of creating a symbol file inside the loop
  //  instead make a function that returns a promise of a symbol file. That promise gets added to a std::vector on
  //  each loop and then when the while loop has finished, we wait on all promises, collecting them.
  while (true) {
    // means we've hit some "entry" point in the linker-debugger interface; we need to wait for RT_CONSISTENT to
    // safely read "link map" containing the shared objects
    if (rdebug_ext.base.r_state != rdebug_ext.base.RT_CONSISTENT) {
      return;
    }
    auto linkmap = TPtr<link_map>{rdebug_ext.base.r_map};
    while (linkmap != nullptr) {
      link_map map = read_type(linkmap);
      auto name_ptr = TPtr<char>{map.l_name};
      const auto path = read_string(name_ptr);
      if (path) {
        auto symbolFile = createNewOrCopyIfUniqueSymbolFile(*this, *path, map.l_addr);
        if (symbolFile) {
          obj_files.push_back(symbolFile);
          register_symbol_file(symbolFile, false);
        }
      }
      linkmap = TPtr<link_map>{map.l_next};
    }
    const auto next = TPtr<r_debug_extended>{rdebug_ext.r_next};
    if (next != nullptr) {
      rdebug_ext = read_type(next);
    } else {
      break;
    }
  }

  do_breakpoints_update(std::move(obj_files));
}

bool
TraceeController::is_null_unwinder(sym::Unwinder *unwinder) const noexcept
{
  return unwinder == null_unwinder;
}

bool
TraceeController::independent_task_resume_control() noexcept
{
  return false;
}

utils::ScopedFd &
TraceeController::mem_fd() noexcept
{
  return procfs_memfd;
}

TaskInfo *
TraceeController::get_task(pid_t tid) noexcept
{
  for (auto &t : threads) {
    if (t.tid == tid)
      return &t;
  }
  return nullptr;
}

std::optional<TaskWaitResult>
TraceeController::wait_pid(TaskInfo *requested_task) noexcept
{
  const auto tid = requested_task == nullptr ? -1 : requested_task->tid;
  return waitpid_block(tid).transform([](auto &&wpid) { return process_status(wpid.tid, wpid.status); });
}

void
TraceeController::new_task(Tid tid, bool ui_update) noexcept
{
  VERIFY(tid != 0, "Invalid tid {}", tid);
  ASSERT(!has_task(tid), "Task {} has already been created!", tid);
  threads.push_back(TaskInfo::create_running(tid));

  ASSERT(std::ranges::all_of(threads, [](TaskInfo &t) { return t.tid != 0; }),
         "Fucking hidden move construction fucked a Task in the ass and gave it 0 as pid");
  if (ui_update) {
    const auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Started, tid};
    Tracer::Instance->post_event(evt);
  }
}

bool
TraceeController::has_task(Tid tid) noexcept
{
  for (const auto &task : threads) {
    if (task.tid == tid)
      return true;
  }
  return false;
}

void
TraceeController::resume_target(RunType type) noexcept
{
  DLOG("mdb", "[supervisor]: resume tracee {}", to_str(type));
  stop_all_requested = false;
  for (auto &t : threads) {
    if (t.can_continue()) {
      resume_task(t, type);
    }
  }
}

void
TraceeController::resume_task(TaskInfo &task, RunType type) noexcept
{
  stop_all_requested = false;
  // The breakpoint location which loc_stat refers to, may have been deleted; as such we don't need to step over
  // that breakpoint any more but we will need to remove the loc stat on this task.
  if (task.loc_stat) {
    auto location = pbps.location_at(task.loc_stat->loc);
    if (location) {
      task.step_over_breakpoint(this, type);
    } else {
      task.remove_bpstat();
      task.ptrace_resume(type);
    }
  } else {
    task.ptrace_resume(type);
  }
}

void
TraceeController::stop_all(TaskInfo *requesting_task) noexcept
{
  DLOG("mdb", "Stopping all threads")
  stop_all_requested = true;
  for (auto &t : threads) {
    if (!t.user_stopped && !t.tracer_stopped) {
      DLOG("mdb", "Stopping {}", t.tid);
      tgkill(task_leader, t.tid, SIGSTOP);
      t.set_stop();
    } else if (t.tracer_stopped) {
      // we're in a tracer-stop, not in a user-stop, so we need no stopping, we only need to inform ourselves that
      // we upgraded our tracer-stop to a user-stop
      t.set_stop();
    }
    // if the stop is requested by `requesting_task` we don't want
    // to remove it's ptrace action as it might be the one requesting the stop
    if (&t != requesting_task) {
      auto action = ptracestop_handler->get_proceed_action(t);
      if (action) {
        action->cancel();
        ptracestop_handler->remove_action(t);
      }
    }
  }
}

void
TraceeController::reap_task(TaskInfo &task) noexcept
{
  auto it = std::ranges::find_if(threads, [&](auto &t) { return t.tid == task.tid; });
  VERIFY(it != std::end(threads), "Could not find Task with pid {}", task.tid);
  task.exited = true;
  Tracer::Instance->thread_exited({.pid = task_leader, .tid = it->tid}, it->wait_status.exit_code);
  if (task.tid == task_leader) {
    awaiter_thread->set_process_exited();
  }
}

TaskInfo *
TraceeController::register_task_waited(TaskWaitResult wait) noexcept
{
  ASSERT(has_task(wait.tid), "Target did not contain task {}", wait.tid);
  auto task = get_task(wait.tid);
  task->set_taskwait(wait);
  task->tracer_stopped = true;
  return task;
}

AddrPtr
TraceeController::get_caching_pc(TaskInfo &t) noexcept
{
  if (t.rip_dirty) {
    t.cache_registers();
    return t.registers->rip;
  } else {
    return t.registers->rip;
  }
}

void
TraceeController::set_pc(TaskInfo &t, AddrPtr addr) noexcept
{
  constexpr auto rip_offset = offsetof(user_regs_struct, rip);
  VERIFY(ptrace(PTRACE_POKEUSER, t.tid, rip_offset, addr.get()) != -1, "Failed to set RIP register");
  t.registers->rip = addr;
  t.rip_dirty = false;
}

void
TraceeController::set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept
{
  ASSERT(has_task(tid), "Unknown task {}", tid);
  task_vm_infos[tid] = vm_info;
}

void
TraceeController::emit_stopped_at_breakpoint(LWP lwp, u32 bp_id, bool all_stopped) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  DLOG("mdb", "[dap event]: stopped at breakpoint {} emitted", bp_id);
  auto evt = new ui::dap::StoppedEvent{
      ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", all_stopped};
  evt->bp_ids.push_back(bp_id);
  Tracer::Instance->post_event(evt);
}

void
TraceeController::emit_stepped_stop(LWP lwp) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  emit_stepped_stop(lwp, "Stepping finished", false);
}

void
TraceeController::emit_stepped_stop(LWP lwp, std::string_view message, bool all_stopped) noexcept
{
  Tracer::Instance->post_event(
      new ui::dap::StoppedEvent{ui::dap::StoppedReason::Step, message, lwp.tid, {}, "", all_stopped});
}

void
TraceeController::emit_signal_event(LWP lwp, int signal) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  Tracer::Instance->post_event(new ui::dap::StoppedEvent{
      ui::dap::StoppedReason::Exception, fmt::format("Signalled {}", signal), lwp.tid, {}, "", true});
}

void
TraceeController::emit_stopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool all_stopped,
                               std::vector<int> bps_hit) noexcept
{
  Tracer::Instance->post_event(new ui::dap::StoppedEvent{reason, message, tid, bps_hit, message, all_stopped});
}

void
TraceeController::emit_breakpoint_event(std::string_view reason, const UserBreakpoint &bp,
                                        std::optional<std::string> message) noexcept
{
  Tracer::Instance->post_event(new ui::dap::BreakpointEvent{reason, message, &bp});
}

utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
TraceeController::get_or_create_bp_location(AddrPtr addr, bool attempt_src_resolve) noexcept
{
  const auto loc = pbps.location_at(addr);
  if (loc) {
    return loc;
  }

  auto res = install_software_bp_loc(addr);
  if (!res.is_expected()) {
    return res;
  }
  const auto original_byte = res.take_value();

  if (attempt_src_resolve) {
    auto obj = find_obj_by_pc(addr);
    auto srcs = obj->getSourceCodeFiles(addr);
    for (auto src : srcs) {
      if (src.address_bounds().contains(addr)) {
        if (auto lte = src.find_lte_by_pc(addr).transform([](auto v) { return v.get(); }); lte) {
          return BreakpointLocation::CreateLocationWithSource(
              addr, original_byte, std::make_unique<LocationSourceInfo>(src.path(), lte->line, u32{lte->column}));
        }
      }
    }
  }
  return BreakpointLocation::CreateLocation(addr, original_byte);
}

utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
TraceeController::get_or_create_bp_location(AddrPtr addr, AddrPtr base,
                                            sym::dw::SourceCodeFile &src_code_file) noexcept
{
  const auto loc = pbps.location_at(addr);
  if (loc) {
    return loc;
  }

  auto lte = src_code_file.find_by_pc(base, addr).transform([](auto v) { return v.get(); });
  ASSERT(lte, "You're using this function wrong. Expected to find address {} inside the source file {}", addr,
         src_code_file.full_path->c_str());
  auto res = install_software_bp_loc(addr);
  if (!res.is_expected()) {
    return res;
  }
  auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocationWithSource(
      addr, original_byte,
      std::make_unique<LocationSourceInfo>(src_code_file.full_path->string(), lte->line, u32{lte->column}));
}

utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
TraceeController::get_or_create_bp_location(AddrPtr addr,
                                            std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept
{
  const auto loc = pbps.location_at(addr);
  if (loc) {
    return loc;
  }

  auto res = install_software_bp_loc(addr);
  if (!res.is_expected()) {
    return res.take_error();
  }
  auto original_byte = res.take_value();
  if (sourceLocInfo) {
    return BreakpointLocation::CreateLocationWithSource(
        addr, original_byte, std::make_unique<LocationSourceInfo>(std::move(sourceLocInfo.value())));
  } else {
    return BreakpointLocation::CreateLocation(addr, original_byte);
  }
}

std::optional<std::shared_ptr<BreakpointLocation>>
TraceeController::reassess_bploc_for_symfile(SymbolFile &symbol_file, UserBreakpoint &user) noexcept
{
  if (auto specPtr = user.user_spec(); specPtr != nullptr) {
    auto objfile = symbol_file.objectFile();
    switch (specPtr->index()) {
    case UserBreakpoint::SOURCE_BREAKPOINT: {
      const auto &spec = std::get<std::pair<std::string, SourceBreakpointSpec>>(*specPtr);
      if (auto source_code_file = objfile->get_source_file(spec.first); source_code_file) {
        if (auto lte = source_code_file->first_linetable_entry(symbol_file.baseAddress, spec.second.line,
                                                               spec.second.column);
            lte) {
          const auto pc = lte->pc;

          if (auto res = get_or_create_bp_location(pc, symbol_file.baseAddress, *source_code_file);
              res.is_expected()) {
            return res.take_value();
          }
        }
      }
    } break;
    case UserBreakpoint::FUNCTION_BREAKPOINT: {
      const auto &spec = std::get<FunctionBreakpointSpec>(*specPtr);
      auto result = symbol_file.lookup_by_spec(spec);

      if (auto it = std::find_if(result.begin(), result.end(),
                                 [](const auto &it) { return it.loc_src_info.has_value(); });
          it != end(result)) {
        if (auto res = get_or_create_bp_location(it->address, std::move(it->loc_src_info.value()));
            res.is_expected()) {
          return res.take_value();
        }
      } else {
        for (auto &&lookup : result) {
          if (auto res = get_or_create_bp_location(lookup.address, false); res.is_expected()) {
            return res.take_value();
          }
        }
      }
    } break;
    case UserBreakpoint::INSTRUCTION_BREAKPOINT:
      const auto &spec = std::get<InstructionBreakpointSpec>(*specPtr);
      auto addr_opt = to_addr(spec.instructionReference);
      ASSERT(addr_opt.has_value(), "Failed to convert instructionReference to valid address");
      const auto addr = addr_opt.value();
      auto srcs = symbol_file.getSourceCodeFiles(addr);
      for (auto src : srcs) {
        if (src.address_bounds().contains(addr)) {
          if (auto iter = src.find_lte_by_pc(addr - symbol_file.baseAddress); iter) {
            if (auto res = get_or_create_bp_location(addr, false); res.is_expected()) {
              return res.take_value();
            }
          }
        }
      }
      break;
    }
  }

  // No new breakpoint location could be found in symbol file.
  return std::nullopt;
}

void
TraceeController::do_breakpoints_update(std::vector<std::shared_ptr<SymbolFile>> &&new_symbol_files) noexcept
{
  DLOG("mdb", "[breakpoints]: Updating breakpoints due to new symbol files");

  // Check all existing breakpoints and those who are verified = false, check if they can be verified against the
  // new object files (and thus actually be set)
  auto non_verified = pbps.non_verified();
  for (auto &user : non_verified) {
    for (auto &symbol_file : new_symbol_files) {
      // this user breakpoint was verified on previous iteration (i.e in another symbol file)
      if (user->verified())
        break;

      if (auto bploc = reassess_bploc_for_symfile(*symbol_file, *user); bploc) {
        user->update_location(std::move(bploc.value()));
        pbps.add_bp_location(user.get());
        emit_breakpoint_event("changed", *user, std::optional<std::string>{});
      }
    }
  }

  // Create new breakpoints, based on source specification or fn name spec, if they exist in new object files
  for (auto &&sym : new_symbol_files) {
    auto obj = sym->objectFile();
    for (const auto &source_file : pbps.sources_with_bpspecs()) {
      auto &file_bp_map = pbps.bps_for_source(source_file);
      if (auto source_code_file = obj->get_source_file(source_file); source_code_file) {
        for (auto &[desc, user_ids] : file_bp_map) {
          if (auto lte = source_code_file->first_linetable_entry(sym->baseAddress, desc.line, desc.column); lte) {
            const auto pc = lte->pc;
            bool same_src_loc_different_pc = false;
            for (const auto id : user_ids) {
              auto user = pbps.get_user(id);
              if (user->address() != pc) {
                same_src_loc_different_pc = true;
              }
            }
            if (same_src_loc_different_pc) {
              std::unique_ptr<UserBpSpec> spec =
                  std::make_unique<UserBpSpec>(std::make_pair(std::string{source_file}, desc));
              auto user = pbps.create_loc_user<Breakpoint>(
                  *this, get_or_create_bp_location(pc, sym->baseAddress, *source_code_file), task_leader,
                  LocationUserKind::Source, std::nullopt, std::nullopt, !independent_task_resume_control(),
                  std::move(spec));
              emit_breakpoint_event("new", *user, {});
              user_ids.push_back(user->id);
              DLOG("mdb", "[bkpt:source]: added bkpt at 0x{}", pc);
            }
          }
        }
      }
    }

    for (auto &[fn, ids] : pbps.fn_breakpoints) {
      auto result = sym->lookup_by_spec(fn);
      for (auto &&lookup : result) {
        auto user = pbps.create_loc_user<Breakpoint>(
            *this, get_or_create_bp_location(lookup.address, std::move(lookup.loc_src_info)), task_leader,
            LocationUserKind::Function, std::nullopt, std::nullopt, !independent_task_resume_control(),
            std::make_unique<UserBpSpec>(fn));
        emit_breakpoint_event("new", *user, {});
        ids.push_back(user->id);
      }
    }
  }
}

void
TraceeController::update_source_bps(const std::filesystem::path &source_filepath,
                                    std::vector<SourceBreakpointSpec> &&add,
                                    const std::vector<SourceBreakpointSpec> &remove) noexcept
{
  UserBreakpoints::SourceFileBreakpointMap &map = pbps.bps_for_source(source_filepath.string());

  Set<SourceBreakpointSpec> not_set{add.begin(), add.end()};

  for (auto symbol_file : symbol_files) {
    auto obj = symbol_file->objectFile();

    if (SourceCodeFile::ShrPtr source_code_file = obj->get_source_file(source_filepath); source_code_file) {
      for (const auto &src_bp : add) {
        if (auto lte =
                source_code_file->first_linetable_entry(symbol_file->baseAddress, src_bp.line, src_bp.column);
            lte) {
          const auto pc = lte->pc;
          auto user = pbps.create_loc_user<Breakpoint>(
              *this, get_or_create_bp_location(pc, symbol_file->baseAddress, *source_code_file), task_leader,
              LocationUserKind::Source, std::nullopt, std::nullopt, !independent_task_resume_control(),
              std::make_unique<UserBpSpec>(std::make_pair(source_filepath.string(), src_bp)));
          map[src_bp].push_back(user->id);
          DLOG("mdb", "[bkpt:source]: added bkpt at 0x{}", pc);
          if (const auto it = not_set.find(src_bp); it != std::end(not_set)) {
            not_set.erase(it);
          }
        }
      }
    }
  }

  // set User Breakpoints without breakpoint location; i.e. "pending" breakpoints, in GDB nomenclature
  for (auto &&srcbp : not_set) {
    auto spec = std::make_unique<UserBpSpec>(std::make_pair(source_filepath.string(), srcbp));
    auto user = pbps.create_loc_user<Breakpoint>(*this, BpErr{ResolveError{.spec = spec.get()}}, task_leader,
                                                 LocationUserKind::Source, std::nullopt, std::nullopt,
                                                 !independent_task_resume_control(), std::move(spec));
    map[srcbp].push_back(user->id);
  }

  for (const auto &bp : remove) {
    auto iter = map.find(bp);
    for (const auto id : iter->second) {
      pbps.remove_bp(id);
    }
    map.erase(map.find(bp));
  }
}

void
TraceeController::set_source_breakpoints(const std::filesystem::path &source_filepath,
                                         const Set<SourceBreakpointSpec> &bps) noexcept
{
  const UserBreakpoints::SourceFileBreakpointMap &map = pbps.bps_for_source(source_filepath.string());
  std::vector<SourceBreakpointSpec> remove{};
  std::vector<SourceBreakpointSpec> add{};
  for (const auto &[b, id] : map) {
    if (!bps.contains(b)) {
      remove.push_back(b);
    }
  }

  for (const auto &b : bps) {
    if (!map.contains(b)) {
      add.push_back(b);
    }
  }

  update_source_bps(source_filepath, std::move(add), remove);
}

void
TraceeController::set_instruction_breakpoints(const Set<InstructionBreakpointSpec> &bps) noexcept
{
  std::vector<InstructionBreakpointSpec> add{};
  std::vector<InstructionBreakpointSpec> remove{};

  for (const auto &[bp, id] : pbps.instruction_breakpoints) {
    if (!bps.contains(bp)) {
      remove.push_back(bp);
    }
  }

  for (const auto &bp : bps) {
    if (!pbps.instruction_breakpoints.contains(bp)) {
      add.push_back(bp);
    }
  }

  for (const auto &bp : add) {
    auto addr = to_addr(bp.instructionReference).value();
    auto symbol_file = find_obj_by_pc(addr);
    auto srcs = symbol_file != nullptr ? symbol_file->getSourceCodeFiles(addr)
                                       : std::vector<sym::dw::RelocatedSourceCodeFile>{};
    bool was_not_set = true;
    for (auto src : srcs) {
      if (src.address_bounds().contains(addr)) {
        if (auto iter = src.find_lte_by_pc(addr); iter) {
          const auto user = pbps.create_loc_user<Breakpoint>(
              *this, get_or_create_bp_location(addr, symbol_file->baseAddress, src.get()), task_leader,
              LocationUserKind::Address, std::nullopt, std::nullopt, !independent_task_resume_control(),
              std::make_unique<UserBpSpec>(bp));
          pbps.instruction_breakpoints[bp] = user->id;
          was_not_set = false;
          break;
        }
      }
    }
    if (was_not_set) {
      const auto user = pbps.create_loc_user<Breakpoint>(
          *this, get_or_create_bp_location(addr, false), task_leader, LocationUserKind::Address, std::nullopt,
          std::nullopt, !independent_task_resume_control(), std::make_unique<UserBpSpec>(bp));
      pbps.instruction_breakpoints[bp] = user->id;
    }
  }

  for (const auto &bp : remove) {
    auto iter = pbps.instruction_breakpoints.find(bp);
    ASSERT(iter != std::end(pbps.instruction_breakpoints), "Expected to find breakpoint");
    pbps.remove_bp(iter->second);
    pbps.instruction_breakpoints.erase(iter);
  }
}

void
TraceeController::set_fn_breakpoints(const Set<FunctionBreakpointSpec> &bps) noexcept
{
  std::vector<FunctionBreakpointSpec> remove{};
  std::vector<FunctionBreakpointSpec> add{};
  for (const auto &[b, id] : pbps.fn_breakpoints) {
    if (!bps.contains(b)) {
      remove.push_back(b);
    }
  }

  for (const auto &b : bps) {
    if (!pbps.fn_breakpoints.contains(b)) {
      add.push_back(b);
    }
  }

  std::unordered_map<FunctionBreakpointSpec, bool> spec_set{};
  for (const auto &fn : add)
    spec_set[fn] = false;

  for (auto &sym : symbol_files) {
    for (const auto &fn : add) {
      auto result = sym->lookup_by_spec(fn);
      bool spec_empty_result = true;
      for (auto &&lookup : result) {
        auto user = pbps.create_loc_user<Breakpoint>(
            *this, get_or_create_bp_location(lookup.address, std::move(lookup.loc_src_info)), task_leader,
            LocationUserKind::Function, std::nullopt, std::nullopt, !independent_task_resume_control(),
            std::make_unique<UserBpSpec>(fn));
        pbps.fn_breakpoints[fn].push_back(user->id);
        spec_set[fn] = true;
      }
      if (spec_empty_result) {
        spec_set[fn] = spec_set[fn] || false;
      }
    }
  }

  for (auto &&[spec, was_set] : spec_set) {
    if (!was_set) {
      auto spec_ptr = std::make_unique<UserBpSpec>(std::move(spec));
      auto user = pbps.create_loc_user<Breakpoint>(*this, BpErr{ResolveError{.spec = spec_ptr.get()}}, task_leader,
                                                   LocationUserKind::Function, std::nullopt, std::nullopt,
                                                   !independent_task_resume_control(), std::move(spec_ptr));
    }
  }

  for (const auto &to_remove : remove) {
    auto iter = pbps.fn_breakpoints.find(to_remove);
    ASSERT(iter != std::end(pbps.fn_breakpoints), "Expected to find fn breakpoint in map");

    for (auto id : iter->second) {
      pbps.remove_bp(id);
    }
    pbps.fn_breakpoints.erase(iter);
  }
}

void
TraceeController::remove_breakpoint(u32 bp_id) noexcept
{
  pbps.remove_bp(bp_id);
}

bool
TraceeController::kill() noexcept
{
  bool done = ptrace(PTRACE_KILL, task_leader, nullptr, nullptr) != -1;
  bool threads_done = false;
  for (const auto &t : threads) {
    threads_done = threads_done && (ptrace(PTRACE_KILL, t.tid, nullptr, nullptr) != -1);
  }
  return done || threads_done;
}

bool
TraceeController::terminate_gracefully() noexcept
{
  DLOG("mdb", "[TraceeController]: terminate gracefully");
  if (is_running()) {
    stop_all(nullptr);
  }
  return ::kill(task_leader, SIGKILL) == 0;
}

bool
TraceeController::detach() noexcept
{
  if (is_running()) {
    stop_all(nullptr);
  }
  std::vector<std::pair<Tid, int>> errs;
  for (const auto &t : threads) {
    const auto res = ptrace(PTRACE_DETACH, t.tid, 0, 0);
    if (res == -1)
      errs.push_back(std::make_pair(t.tid, errno));
  }

  // todo(simon): construct a way to let this information bubble up to caller
  return errs.empty();
}

void
TraceeController::process_exec(TaskInfo &t) noexcept
{
  DLOG("mdb", "Processing EXEC for {}", t.tid);
  reopen_memfd();
  t.cache_registers();
  read_auxv(t);
  install_loader_breakpoints();
}

Tid
TraceeController::process_clone(TaskInfo &t) noexcept
{
  DLOG("mdb", "Processing CLONE for {}", t.tid);
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  t.cache_registers();
  pid_t np = -1;
  if (t.registers->orig_rax == SYS_clone) {
    const TPtr<void> stack_ptr = sys_arg_n<2>(*t.registers);
    const TPtr<int> child_tid = sys_arg_n<4>(*t.registers);
    const u64 tls = sys_arg_n<5>(*t.registers);
    np = read_type(child_tid);
    if (!has_task(np))
      new_task(np, true);
    get_task(np)->initialize();
    set_task_vm_info(np, TaskVMInfo{.stack_low = stack_ptr, .stack_size = 0, .tls = tls});
    return np;
  } else if (t.registers->orig_rax == SYS_clone3) {
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(*t.registers);
    const auto res = read_type(ptr);
    np = read_type(TPtr<pid_t>{res.parent_tid});
    if (!has_task(np))
      new_task(np, true);
    // by this point, the task has cloned _and_ it's continuable because the parent has been told
    // that "hey, we're ok". Why on earth a pre-finished clone can be waited on, I will never know.
    get_task(np)->initialize();
    // task backing storage may have re-allocated and invalidated this pointer.
    set_task_vm_info(np, TaskVMInfo::from_clone_args(res));
    return np;
  } else {
    PANIC("Unknown clone syscall!");
  }
}

bool
TraceeController::execution_not_ended() const noexcept
{
  return !threads.empty();
}

bool
TraceeController::is_running() const noexcept
{
  return std::any_of(threads.cbegin(), threads.cend(), [](const TaskInfo &t) {
    DLOG("mdb", "Thread {} stopped={}", t.tid, t.is_stopped());
    return !t.is_stopped();
  });
}

void
TraceeController::register_symbol_file(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept
{
  const auto it = std::find_if(symbol_files.begin(), symbol_files.end(),
                               [&symbolFile](auto &s) { return symbolFile->path() == s->path(); });
  if (it != std::end(symbol_files)) {
    const auto same_bounds = symbolFile->pc_bounds == (*it)->pc_bounds;
    DLOG("mdb", "[symbol file]: Already added {} at {} .. {}; new is at {}..{} - Same range?: {}",
         symbolFile->path().c_str(), (*it)->low_pc(), (*it)->high_pc(), symbolFile->low_pc(),
         symbolFile->high_pc(), same_bounds)
    return;
  }
  symbol_files.emplace_back(symbolFile);

  if (isMainExecutable)
    main_executable = symbol_files.back();

  // todo(simon): optimization possible; insert in a sorted fashion instead.
  std::sort(symbol_files.begin(), symbol_files.end(), [&symbolFile](auto &&a, auto &&b) {
    ASSERT(a->low_pc() != b->low_pc(),
           "[{}]: Added object files with identical address ranges. We screwed something up, for sure\na={}\nb={}",
           symbolFile->path().c_str(), a->path().c_str(), b->path().c_str());
    return a->low_pc() < b->low_pc() && a->high_pc() < b->high_pc();
  });
  new_objectfile.emit(symbolFile.get());
}

// Debug Symbols Related Logic
void
TraceeController::register_object_file(std::shared_ptr<ObjectFile> obj, bool is_main_executable,
                                       AddrPtr relocated_base) noexcept
{
  ASSERT(obj != nullptr, "Object file is null");
  register_symbol_file(SymbolFile::Create(*this, obj, relocated_base), is_main_executable);
}

struct AuxvPair
{
  u64 key, value;
};

void
TraceeController::read_auxv(const TaskInfo &task)
{
  ASSERT(task.wait_status.ws == WaitStatusKind::Execed,
         "Reading AUXV using this function does not make sense if's not *right* after an EXEC");
  TPtr<i64> stack_ptr = task.registers->rsp;
  i64 argc = read_type(stack_ptr);

  stack_ptr += argc + 1;
  ASSERT(read_type(stack_ptr) == 0, "Expected null terminator after argv at {}", stack_ptr);
  stack_ptr++;
  auto envp = stack_ptr.as<const char *>();
  // we're at the envp now, that pointer list is also terminated by a nullptr
  while (read_type(envp) != nullptr) {
    envp++;
  }
  // We should now be at Auxilliary Vector Table (see `man getauxval` for info, we're interested in the
  // interpreter base address)

  envp++;
  // cast it to our own type
  auto aux_ptr = envp.as<AuxvPair>();
  std::vector<AuxvPair> auxv{};
  for (;;) {
    auto kvp = read_type(aux_ptr);
    auxv.push_back(kvp);
    // terminated by a "null entry"
    if (kvp.key == 0) {
      break;
    }
    aux_ptr++;
  }

  for (const auto &kvp : auxv) {
    if (kvp.key == AT_BASE) {
      interpreter_base = kvp.value;
    }
    if (kvp.key == AT_ENTRY) {
      entry = kvp.value;
    }
  }

  ASSERT(entry.has_value() && interpreter_base.has_value(), "Expected ENTRY and INTERPRETER_BASE to be found");
}

TargetSession
TraceeController::session_type() const noexcept
{
  return session;
}

std::string
TraceeController::get_thread_name(Tid tid) const noexcept
{
  Path p = fmt::format("/proc/{}/task/{}/comm", task_leader, tid);
  utils::ScopedFd f = utils::ScopedFd::open_read_only(p);
  char buf[16];
  std::memset(buf, 0, 16);
  ::read(f, buf, 16);
  auto name = std::string{buf};
  if (name.ends_with("\n")) {
    name.pop_back();
  }
  return name;
}

std::vector<u8>
TraceeController::read_to_vec(AddrPtr addr, u64 bytes) noexcept
{
  std::vector<u8> data{};
  data.resize(bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto read_bytes = pread64(mem_fd().get(), data.data() + total_read, bytes - total_read, addr);
    if (-1 == read_bytes || 0 == read_bytes) {
      PANIC(fmt::format("Failed to proc_fs read from {}", addr));
    }
    total_read += read_bytes;
  }
  if (total_read != data.size()) {
    PANIC("failed to read into std::vector");
  }
  return data;
}

utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead>
TraceeController::safe_read(AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = utils::ByteBuffer::create(bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto read_bytes = pread64(mem_fd().get(), buffer->next(), bytes - total_read, addr + total_read);
    if (-1 == read_bytes || 0 == read_bytes) {
      return utils::unexpected(NonFullRead{std::move(buffer), static_cast<u32>(bytes - total_read), errno});
    }
    buffer->wrote_bytes(read_bytes);
    total_read += read_bytes;
  }
  return utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead>{std::move(buffer)};
}

utils::StaticVector<u8>::OwnPtr
TraceeController::read_to_vector(AddrPtr addr, u64 bytes) noexcept
{
  auto data = std::make_unique<utils::StaticVector<u8>>(bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto read_bytes = pread64(mem_fd().get(), data->data_ptr() + total_read, bytes - total_read, addr);
    if (-1 == read_bytes || 0 == read_bytes) {
      PANIC(fmt::format("Failed to proc_fs read from {}", addr));
    }
    total_read += read_bytes;
  }
  data->set_size(total_read);
  return data;
}

std::optional<std::string>
TraceeController::read_string(TraceePointer<char> address) noexcept
{
  std::string result;
  if (address == nullptr)
    return std::nullopt;
  auto ch = read_type<char>(address);
  while (ch != 0) {
    result.push_back(ch);
    address += 1;
    ch = read_type<char>(address);
  }
  if (result.empty())
    return std::nullopt;
  return result;
}

void
TraceeController::reaped_events() noexcept
{
  awaiter_thread->reaped_events();
}

/** Called after an exec has been processed and we've set up the necessary data structures
  to manage it.*/
void
TraceeController::start_awaiter_thread() noexcept
{
  awaiter_thread->start_awaiter_thread(this);
}

sym::Frame
TraceeController::current_frame(TaskInfo &task) noexcept
{
  const auto pc = task.pc();
  const auto obj = find_obj_by_pc(pc);
  if (obj == nullptr) {
    return sym::Frame{nullptr, task, 0, 0, pc, nullptr};
  }
  auto cus_matching_addr = obj->getCusFromPc(pc);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  for (auto cu : cus_matching_addr) {
    for (auto &src : obj->objectFile()->source_units()) {
      if (cu == src.get_dwarf_unit()) {
        if (auto fn = src.get_fn_by_pc(obj->unrelocate(pc)); fn) {
          return sym::Frame{obj, task, 0, 0, pc, fn};
        }
      }
    }
  }

  if (auto min_sym = obj->searchMinSymFnInfo(pc); min_sym != nullptr)
    return sym::Frame{obj, task, 0, 0, pc, min_sym};
  else
    return sym::Frame{obj, task, 0, 0, pc, nullptr};
}

sym::UnwinderSymbolFilePair
TraceeController::get_unwinder_from_pc(AddrPtr pc) noexcept
{
  for (auto &symbol_file : symbol_files) {
    const auto &u = symbol_file->objectFile()->unwinder;
    const auto addr_range = u->addr_range;
    const auto unrelocated = symbol_file->unrelocate(pc);
    if (addr_range.contains(unrelocated)) {
      return sym::UnwinderSymbolFilePair{u.get(), symbol_file.get()};
    }
  }
  return sym::UnwinderSymbolFilePair{null_unwinder, nullptr};
}

std::vector<AddrPtr> &
TraceeController::unwind_callstack(TaskInfo *task) noexcept
{
  task->cache_registers();
  if (!task->call_stack->dirty) {
    return task->call_stack->pcs;
  } else {
    task->call_stack->dirty = false;
    task->call_stack->pcs.clear();
    auto &frame_pcs = task->call_stack->pcs;
    u8 stack_storage[100 * sizeof(std::uintptr_t)];
    std::pmr::monotonic_buffer_resource rsrc{&stack_storage, 100 * sizeof(std::uintptr_t)};

    std::pmr::vector<TPtr<std::uintptr_t>> base_ptrs{&rsrc};
    base_ptrs.reserve(50);
    auto bp = task->registers->rbp;
    base_ptrs.push_back(bp);
    while (true) {
      TPtr<std::uintptr_t> bp_addr = base_ptrs.back();
      const auto prev_bp = read_type_safe(bp_addr).transform([](auto v) { return TPtr<std::uintptr_t>{v}; });
      if (auto prev = prev_bp.value_or(0x0); prev == bp_addr || !(prev > TPtr<std::uintptr_t>{1}))
        break;
      base_ptrs.push_back(*prev_bp);
    }

    frame_pcs.push_back(task->registers->rip);
    bool inside_prologue = false;
    auto obj = find_obj_by_pc(task->registers->rip);

    auto syminfos = obj->getSourceInfos(task->registers->rip);
    sym::CompilationUnit *current_symtab = nullptr;
    if (!syminfos.empty()) {
      for (auto *symtab : syminfos) {
        auto lt = symtab->get_linetable(obj);
        ASSERT(lt, "No line table for {}", symtab->name());
        auto it = lt->find_by_pc(frame_pcs.front());
        if (it != std::end(*lt) && it.get().prologue_end) {
          inside_prologue = true;
          current_symtab = symtab;
          break;
        }
      }
    }

    for (auto bp_it = base_ptrs.begin(); bp_it != base_ptrs.end(); ++bp_it) {
      const auto ret_addr = read_type_safe<TPtr<std::uintptr_t>>({offset(*bp_it, 8)});
      if (ret_addr) {
        frame_pcs.push_back(ret_addr->as_void());
      }
    }

    // NB(simon): tracee hasn't finalized it's activation record; we need to perform some heuristics
    // to actually determine return address. For now, this is it.
    if (inside_prologue) {
      TPtr<std::uintptr_t> ret_addr = task->registers->rsp;
      auto ret_val_a = read_type_safe(ret_addr).value_or(0);

      bool resolved = false;
      if (ret_val_a != 0) {
        if (current_symtab && current_symtab->start_pc() <= ret_val_a && current_symtab->end_pc() >= ret_val_a) {
          frame_pcs.insert(frame_pcs.begin() + 1, ret_val_a);
          resolved = true;
        }
      }

      if (!resolved) {
        auto ret_val_b = read_type_safe(offset(ret_addr, 8)).value_or(0);
        if (!resolved && ret_val_b != 0) {
          if (current_symtab && current_symtab->start_pc() <= ret_val_b && current_symtab->end_pc() >= ret_val_b) {
            frame_pcs.insert(frame_pcs.begin() + 1, ret_val_b);
          }
        }
      }
    }
    return task->call_stack->pcs;
  }
}

int
TraceeController::new_frame_id(NonNullPtr<SymbolFile> owning_obj, TaskInfo &task) noexcept
{
  const auto res = take_new_varref_id();
  var_refs.emplace(std::piecewise_construct, std::forward_as_tuple(res),
                   std::forward_as_tuple(owning_obj, res, task.tid, res, 0, ui::dap::EntityType::Frame));
  return res;
}

int
TraceeController::new_scope_id(NonNullPtr<SymbolFile> owning_obj, const sym::Frame *frame,
                               ui::dap::ScopeType type) noexcept
{
  const auto res = take_new_varref_id();
  const auto fid = frame->id();
  const auto iter = var_refs.find(fid);
  if (iter == std::end(var_refs))
    PANIC("Expected to find object with variables reference of");
  var_refs.emplace(
      std::piecewise_construct, std::forward_as_tuple(res),
      std::forward_as_tuple(owning_obj, res, iter->second.thread_id, fid, fid, ui::dap::EntityType::Scope, type));
  return res;
}

void
TraceeController::invalidate_stop_state() noexcept
{
  for (auto obj : symbol_files) {
    obj->invalidateVariableReferences();
  }
}

int
TraceeController::new_var_id(int parent_id) noexcept
{
  const auto res = take_new_varref_id();
  const auto it = var_refs.find(parent_id);
  const auto &vr = it->second;
  var_refs.emplace(std::piecewise_construct, std::forward_as_tuple(res),
                   std::forward_as_tuple(vr.object_file, res, int{vr.thread_id}, int{vr.frame_id},
                                         int{vr.parent().value_or(0)}, ui::dap::EntityType::Variable));
  return res;
}

void
TraceeController::reset_variable_references() noexcept
{
  var_refs.clear();
  reset_variable_ref_id();
}

// These two simple functions have been refactored out, because later on in the future
// when we do multiprocess debugging, variable references must be unique across _all_ processes not just inside a
// single process. meaning, both process A and B can't have a variable reference with an id of 2.
int
TraceeController::take_new_varref_id() noexcept
{
  return next_var_ref++;
}

void
TraceeController::reset_variable_ref_id() noexcept
{
  next_var_ref = 1;
}

sym::CallStack &
TraceeController::build_callframe_stack(TaskInfo &task, CallStackRequest req) noexcept
{
  DLOG("mdb", "stacktrace for {}", task.tid);
  task.cache_registers();
  auto &cs_ref = *task.call_stack;
  cs_ref.frames.clear();

  auto frame_pcs = task.return_addresses(this, req);
  for (const auto &[depth, i] : utils::EnumerateView{frame_pcs}) {
    auto frame_pc = i.as_void();
    auto result = find_fn_by_pc(frame_pc);
    if (!result) {
      PANIC("No object file related to pc - that should be impossible.");
    }
    auto &[symbol, obj] = result.value();
    const auto id = new_frame_id(obj, task);
    if (symbol) {
      cs_ref.frames.push_back(sym::Frame{obj, task, depth, id, i.as_void(), symbol});
    } else {
      auto obj = find_obj_by_pc(frame_pc);
      auto min_sym = obj->searchMinSymFnInfo(frame_pc);
      if (min_sym) {
        cs_ref.frames.push_back(sym::Frame{obj, task, depth, id, i.as_void(), min_sym});
      } else {
        DLOG("mdb", "[stackframe]: WARNING, no frame info for pc {}", i.as_void());
        cs_ref.frames.push_back(sym::Frame{obj, task, depth, id, i.as_void(), nullptr});
      }
    }
  }
  cs_ref.dirty = false;
  return cs_ref;
}

SymbolFile *
TraceeController::find_obj_by_pc(AddrPtr addr) noexcept
{
  return utils::find_if(symbol_files, [addr](auto &symbol_file) { return symbol_file->contains(addr); })
      .transform([](auto iterator) { return iterator->get(); })
      .value_or(nullptr);
}

std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>>
TraceeController::find_fn_by_pc(AddrPtr addr) noexcept
{
  const auto obj = find_obj_by_pc(addr);
  if (obj == nullptr)
    return std::nullopt;

  auto cus_matching_addr = obj->getCusFromPc(addr);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  for (auto cu : cus_matching_addr) {
    for (auto &src : obj->objectFile()->source_units()) {
      if (cu == src.get_dwarf_unit()) {
        if (auto fn = src.get_fn_by_pc(obj->unrelocate(addr)); fn)
          return std::make_pair(fn, NonNull(*obj));
      }
    }
  }

  return std::make_pair(nullptr, NonNull(*obj));
}

const ElfSection *
TraceeController::get_text_section(AddrPtr addr) noexcept
{
  const auto obj = find_obj_by_pc(addr);
  if (obj) {
    const auto text = obj->objectFile()->elf->get_section(".text");
    return text;
  }
  return nullptr;
}

u8
TraceeController::write_bp_byte(AddrPtr addr) noexcept
{
  constexpr u8 bkpt = 0xcc;
  auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, addr, nullptr);
  u8 ins_byte = static_cast<u8>(read_value & 0xff);
  u64 installed_bp = ((read_value & ~0xff) | bkpt);
  ptrace(PTRACE_POKEDATA, task_leader, addr, installed_bp);
  return ins_byte;
}

std::optional<u8>
TraceeController::write_breakpoint_at(AddrPtr addr) noexcept
{
  constexpr u8 bkpt = 0xcc;
  const auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, addr, nullptr);
  if (read_value == -1) {
    return std::nullopt;
  }

  const u8 ins_byte = static_cast<u8>(read_value & 0xff);
  const u64 installed_bp = ((read_value & ~0xff) | bkpt);

  if (ptrace(PTRACE_POKEDATA, task_leader, addr, installed_bp) == -1) {
    return std::nullopt;
  }
  return ins_byte;
}

utils::Expected<u8, BpErr>
TraceeController::install_software_bp_loc(AddrPtr addr) noexcept
{
  constexpr u8 bkpt = 0xcc;
  const auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, addr, nullptr);
  if (read_value == -1) {
    return utils::unexpected(BpErr{LocReadError{errno, addr}});
  }

  const u8 ins_byte = static_cast<u8>(read_value & 0xff);
  const u64 installed_bp = ((read_value & ~0xff) | bkpt);

  if (ptrace(PTRACE_POKEDATA, task_leader, addr, installed_bp) == -1) {
    return utils::unexpected(BpErr{LocWriteError{errno, addr}});
  }
  return ins_byte;
}

std::optional<ui::dap::VariablesReference>
TraceeController::var_ref(int variables_reference) noexcept
{
  auto it = std::find_if(var_refs.begin(), var_refs.end(),
                         [vr = variables_reference](auto &kvp) { return kvp.first == vr; });
  if (it != std::end(var_refs))
    return it->second;
  else
    return std::nullopt;
}

std::array<ui::dap::Scope, 3>
TraceeController::scopes_reference(int frame_id) noexcept
{
  using S = ui::dap::Scope;
  const auto f = frame(frame_id);
  auto obj = var_refs.find(f->id())->second.object_file;

  return std::array<S, 3>{S{"Arguments", "arguments", new_scope_id(obj, f, ui::dap::ScopeType::Arguments)},
                          S{"Locals", "locals", new_scope_id(obj, f, ui::dap::ScopeType::Locals)},
                          S{"Registers", "registers", new_scope_id(obj, f, ui::dap::ScopeType::Registers)}};
}

sym::Frame *
TraceeController::frame(int frame_id) noexcept
{
  const auto it = var_refs.find(frame_id);
  if (it == std::end(var_refs))
    PANIC("expected to find frame with frame id");

  auto task = get_task(it->second.thread_id);
  return task->call_stack->get_frame(frame_id);
}

void
TraceeController::notify_all_stopped() noexcept
{
  DLOG("mdb", "[all-stopped]: sending registered notifications");
  // all_stopped_observer.send_notifications();
  all_stop.emit();
}

bool
TraceeController::all_stopped() const noexcept
{
  return std::ranges::all_of(threads, [](const auto &t) { return t.stop_processed(); });
}

void
TraceeController::set_pending_waitstatus(TaskWaitResult wait_result) noexcept
{
  const auto tid = wait_result.tid;
  auto task = get_task(tid);
  ASSERT(task != nullptr, "couldn't find task {}", tid);
  task->wait_status = wait_result.ws;
  task->tracer_stopped = true;
  task->stop_collected = false;
}

bool
TraceeController::ptrace_was_seized() const noexcept
{
  return ptrace_session_seized;
}