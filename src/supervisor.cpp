#include "supervisor.h"
#include "breakpoint.h"
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
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <link.h>
#include <memory_resource>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_set>
#include <utility>
#include <variant>

template <typename T> using Set = std::unordered_set<T>;

TraceeController::TraceeController(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify,
                                   TargetSession session, bool seized, bool open_mem_fd) noexcept
    : task_leader{process_space_id}, object_files{}, main_executable(nullptr), threads{}, bps(process_space_id),
      tracee_r_debug(nullptr), shared_objects(), waiting_for_all_stopped(false), all_stopped_observer(),
      var_refs(), interpreter_base{}, entry{}, session(session),
      ptracestop_handler(new ptracestop::StopHandler{*this}), unwinders(),
      null_unwinder(new sym::Unwinder{nullptr}), ptrace_session_seized(seized)
{
  threads.reserve(256);
  awaiter_thread = std::make_unique<AwaiterThread>(awaiter_notify, process_space_id);
  threads.push_back(TaskInfo::create_running(process_space_id));
  threads.back().initialize();
  if (open_mem_fd) {
    const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
    procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
  }
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
  auto int_path =
      interpreter_path(object_files.front()->parsed_elf, object_files.front()->parsed_elf->get_section(".interp"));
  auto tmp_objfile = mmap_objectfile(int_path);
  ASSERT(tmp_objfile != nullptr, "Failed to mmap the loader binary");
  Elf::parse_elf_owned_by_obj(tmp_objfile, interpreter_base.value());
  tmp_objfile->parsed_elf->parse_min_symbols(AddrPtr{interpreter_base.value()});
  const auto system_tap_sec = tmp_objfile->parsed_elf->get_section(".note.stapsdt");
  const auto probes = parse_stapsdt_note(tmp_objfile->parsed_elf, system_tap_sec);
  tracee_r_debug = get_rdebug_state(tmp_objfile);
  DLOG("mdb", "_r_debug found at {}", tracee_r_debug);
  for (const auto symbol_name : LOADER_SYMBOL_NAMES) {
    if (auto symbol = tmp_objfile->get_min_fn_sym(symbol_name); symbol) {
      const auto addr = symbol->address;
      DLOG("mdb", "Setting ld breakpoint at {}", addr);
      set_tracer_bp(addr.as<u64>(), BpType{}.SharedObj(true));
    }
  }
  delete tmp_objfile;
}

void
TraceeController::on_so_event() noexcept
{
  DLOG("mdb", "so event triggered");
  // tracee_r_debug: TPtr<r_debug> points to tracee memory where r_debug lives
  r_debug_extended rdebug_ext = read_type(tracee_r_debug);
  int new_so_ids[50];
  int new_sos = 0;

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
        const auto so = shared_objects.add_if_new(linkmap, map.l_addr, std::move(*path));
        if (so)
          new_so_ids[new_sos++] = so.value();
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
  DLOG("mdb", "[so event] new={}", new_sos);

  // do simple parsing first, then collect to do extensive processing in parallell
  std::vector<SharedObject::SoId> sos;
  for (auto i = 0; i < new_sos; ++i) {
    auto so = shared_objects.get_so(new_so_ids[i]);
    so->objfile = mmap_objectfile(so->path);
    if (so->objfile) {
      register_object_file(so->objfile, false, so->elf_vma_addr_diff);
      sos.push_back(new_so_ids[i]);
    }
  }
  process_dwarf(sos);
}

bool
TraceeController::is_null_unwinder(sym::Unwinder *unwinder) const noexcept
{
  return unwinder == null_unwinder;
}

void
TraceeController::process_dwarf(std::vector<SharedObject::SoId> sos) noexcept
{
  // todo(simon): make this multi threaded, like the parsing of dwarf for the main executable.
  //  it's fairly simple to get a parallell version going - however, we should do that once the parsing is done
  //  because when/if parsing fails and aborts, with multi threading we might not have the proper time to log
  //  it.
  for (auto so_id : sos) {
    const auto so = shared_objects.get_so(so_id);
    if (so->has_debug_info()) {
      so->objfile->initial_dwarf_setup(Tracer::Instance->get_configuration().dwarf_config());
    }
    Tracer::Instance->post_event(new ui::dap::ModuleEvent{"new", so});
  }
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
  waiting_for_all_stopped = false;
  for (auto &t : threads) {
    if (t.can_continue()) {
      resume_task(t, type);
    }
  }
}

void
TraceeController::resume_task(TaskInfo &task, RunType type) noexcept
{
  waiting_for_all_stopped = false;
  if (task.bstat) {
    task.step_over_breakpoint(this, type);
  } else {
    task.ptrace_resume(type);
  }
}

void
TraceeController::stop_all(TaskInfo *requesting_task) noexcept
{
  DLOG("mdb", "Stopping all threads")
  waiting_for_all_stopped = true;
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
TraceeController::set_addr_breakpoint(TraceePointer<u64> address) noexcept
{
  if (bps.contains(address)) {
    auto bp = bps.get(address.as<void>());
    bp->bp_type.address = true;
    return;
  }
  u8 original_byte = write_bp_byte(address.as_void());
  bps.insert(address.as_void(), original_byte, BpType{}.Addr(true));
}

bool
TraceeController::set_tracer_bp(TPtr<u64> addr, BpType type) noexcept
{
  if (bps.contains(addr)) {
    auto bp = bps.get(addr.as<void>());
    DLOG("mdb", "Configuring bp {} at {} to be tracer bp as well", bp->id, addr);
    bp->bp_type.type |= type.type;
    return true;
  }
  u8 bkpt = 0xcc;
  const auto original_byte = read_type_safe(addr.as<u8>());
  ASSERT(original_byte.has_value(), "Failed to read byte at {}", addr);
  write(addr.as<u8>(), bkpt);
  bps.insert(addr.as_void(), *original_byte, type);
  return true;
}

Breakpoint *
TraceeController::set_finish_fn_bp(TraceePointer<void> addr) noexcept
{
  BpType type = BpType{}.Addr(true).Resume(true);
  if (bps.contains(addr)) {
    auto bp = bps.get(addr.as<void>());
    DLOG("mdb", "Configuring bp {} at {} to be {} bp as well", bp->id, addr, type);
    bp->bp_type.type |= type.type;
    return bp;
  }
  u8 bkpt = 0xcc;
  const auto original_byte = read_type_safe(addr.as<u8>());
  ASSERT(original_byte.has_value(), "Failed to read byte at {}", addr);
  write(addr.as<u8>(), bkpt);
  bps.insert(addr.as_void(), *original_byte, type);
  return bps.get(addr);
}

void
TraceeController::set_fn_breakpoint(std::string_view function_name) noexcept
{
  for (const auto &[id, name] : bps.fn_breakpoint_names) {
    if (name == function_name)
      return;
  }

  std::vector<MinSymbol> matching_symbols;
  for (ObjectFile *obj : object_files) {
    if (auto s = obj->get_min_fn_sym(function_name); s.has_value()) {
      matching_symbols.push_back(*s);
    }
    auto ni = obj->name_index();
    auto res = ni->free_functions.search(function_name).value_or(std::span<sym::dw::DieNameReference>{});
    for (const auto &ref : res) {
      auto die_ref = ref.cu->get_cu_die_ref(ref.die_index);
      auto low_pc = die_ref.read_attribute(Attribute::DW_AT_low_pc);
      if (low_pc) {
        auto addr = obj->parsed_elf->relocate_addr(low_pc->address());
        matching_symbols.emplace_back(function_name, addr, 0);
        DLOG("mdb", "[{}][cu=0x{:x}, die=0x{:x}] found fn {} at low_pc of {}", obj->path.c_str(),
             die_ref.cu->section_offset(), die_ref.die->section_offset, function_name, addr);
      }
    }
  }

  DLOG("mdb", "Found {} matching symbols for {}", matching_symbols.size(), function_name);
  for (const auto &sym : matching_symbols) {
    if (bps.contains(sym.address)) {
      auto bp = bps.get(sym.address);
      bp->bp_type.add_setting(BpType{}.Function(true));
      bps.fn_breakpoint_names[bp->id] = function_name;
    } else {
      auto ins_byte = write_bp_byte(sym.address);
      bps.insert(sym.address, ins_byte, BpType{}.Function(true));
      auto &bp = bps.breakpoints.back();
      bps.fn_breakpoint_names[bp.id] = function_name;
    }
  }
}

void
TraceeController::set_source_breakpoints(const std::filesystem::path &src,
                                         std::vector<SourceBreakpointDescriptor> &&descs) noexcept
{
  DLOG("mdb", "[bkpt:source]: Requested {} new source breakpoints for {}", descs.size(), src.c_str());
  for (auto obj : object_files) {
    if (auto source_code_file = obj->get_source_file(src); source_code_file) {
      DLOG("mdb", "[bkpt:source]: objfile {} has file {}", obj->path.c_str(), src.c_str());
      for (auto &&desc : descs) {
        if (auto lte = source_code_file->first_linetable_entry(desc.line, desc.column); lte) {
          const auto pc = lte->pc;
          if (!bps.contains(pc)) {
            u8 original_byte = write_bp_byte(pc);
            bps.insert(pc, original_byte, BpType{}.Source(true));
            const auto &bp = bps.breakpoints.back();
            bps.source_breakpoints[bp.id] = std::move(desc);
          } else {
            auto bp = bps.get(pc);
            bp->bp_type.source = true;
          }
        }
      }
    }
  }
  logging::get_logging()->log("mdb", fmt::format("Total breakpoints {}", bps.breakpoints.size()));
}

void
TraceeController::emit_stopped_at_breakpoint(LWP lwp, u32 bp_id) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  DLOG("mdb", "[dap event]: stopped at breakpoint {} emitted", bp_id);
  auto evt =
      new ui::dap::StoppedEvent{ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", false};
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
TraceeController::reset_addr_breakpoints(std::vector<AddrPtr> addresses) noexcept
{
  bps.clear(*this, BpType{}.Addr(true));
  for (auto addr : addresses) {
    set_addr_breakpoint(addr.as<u64>());
  }
}

void
TraceeController::reset_fn_breakpoints(std::vector<std::string_view> fn_names) noexcept
{
  bps.clear(*this, BpType{}.Function(true));
  bps.fn_breakpoint_names.clear();
  for (auto fn_name : fn_names) {
    set_fn_breakpoint(fn_name);
  }
}

void
TraceeController::reset_source_breakpoints(const std::filesystem::path &source_filepath,
                                           std::vector<SourceBreakpointDescriptor> &&desc) noexcept
{
  auto type = BpType{}.Source(true);
  std::erase_if(bps.breakpoints, [&](Breakpoint &bp) {
    if (bp.type() & type) {
      // if enabled, and if new setting, means that it's not a combination of any breakpoint types left, disable it
      // and erase it.
      if (bp.bp_type.source && type.source) {
        auto &bp_descriptor = bps.source_breakpoints[bp.id];
        if (source_filepath != bp_descriptor.source_file)
          return false;
        auto it = std::find(desc.begin(), desc.end(), bp_descriptor);
        if (it != std::end(desc)) {
          desc.erase(it);
          return false;
        }
        bps.source_breakpoints.erase(bp.id);
      }
      if (bp.bp_type.function && type.function) {
        bps.fn_breakpoint_names.erase(bp.id);
      }

      // If flipping off all `type` bits in bp results in == 0, means it should be deleted.
      if (bp.enabled && !(bp.type() & type)) {
        bp.disable(task_leader);
        return true;
      } else {
        // turn off all types passed in as `type`, keep the rest
        bp.bp_type.unset(type);
      }
    }
    return false;
  });
  set_source_breakpoints(source_filepath, std::move(desc));
}

void
TraceeController::remove_breakpoint(AddrPtr addr, BpType type) noexcept
{
  bps.remove_breakpoint(addr, type);
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

// Debug Symbols Related Logic
void
TraceeController::register_object_file(ObjectFile *obj, bool is_main_executable,
                                       std::optional<AddrPtr> base_vma) noexcept
{
  ASSERT(obj != nullptr, "Object file is null");
  Elf::parse_elf_owned_by_obj(obj, base_vma.value_or(0));
  object_files.push_back(NonNull(*obj));
  if (!obj->has_elf_symbols) {
    obj->parsed_elf->parse_min_symbols(base_vma.value_or(0));
  }
  if (is_main_executable)
    main_executable = obj;

  auto unwinder = sym::parse_eh(obj, obj->parsed_elf->get_section(".eh_frame"), base_vma.value_or(0));
  const auto section = obj->parsed_elf->get_section(".debug_frame");
  if (section) {
    DLOG("mdb", ".debug_frame section found; parsing DWARF CFI section");
    sym::parse_dwarf_eh(obj->parsed_elf, unwinder.get(), section, -1);
  }

  unwinders.push_back(std::move(unwinder));
  // todo(simon): optimization possible; insert in a sorted fashion instead.
  std::sort(unwinders.begin(), unwinders.end(), [](auto &&a, auto &&b) {
    return a->addr_range.low < b->addr_range.low && a->addr_range.high < b->addr_range.high;
  });
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
  if (const auto symbol = find_fn_by_pc(pc, nullptr); symbol) {
    return sym::Frame{task, 0, 0, pc, symbol};
  }

  auto obj = find_obj_by_pc(pc);
  if (obj == nullptr) {
    return sym::Frame{task, 0, 0, pc, nullptr};
  }
  if (auto min_sym = obj->search_minsym_fn_info(pc); min_sym != nullptr)
    return sym::Frame{task, 0, 0, pc, min_sym};
  else
    return sym::Frame{task, 0, 0, pc, nullptr};
}

sym::Unwinder *
TraceeController::get_unwinder_from_pc(AddrPtr pc) noexcept
{
  for (auto &unwinder : unwinders) {
    if (unwinder->addr_range.contains(pc)) {
      return unwinder.get();
    }
  }
  return null_unwinder;
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

    auto syminfos = obj->get_source_infos(task->registers->rip);
    sym::SourceFileSymbolInfo *current_symtab = nullptr;
    if (!syminfos.empty()) {
      for (auto *symtab : syminfos) {
        auto lt = symtab->get_linetable();
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
TraceeController::new_frame_id(NonNullPtr<ObjectFile> owning_obj, TaskInfo &task) noexcept
{
  const auto res = take_new_varref_id();
  var_refs.emplace(std::piecewise_construct, std::forward_as_tuple(res),
                   std::forward_as_tuple(owning_obj, res, task.tid, res, 0, ui::dap::EntityType::Frame));
  return res;
}

int
TraceeController::new_scope_id(NonNullPtr<ObjectFile> owning_obj, const sym::Frame *frame,
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
  for (auto obj : object_files) {
    obj->invalidate_variable_references();
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
    ObjectFile *obj;
    auto symbol = find_fn_by_pc(frame_pc, &obj);
    if (obj == nullptr) {
      PANIC("No object file related to pc - that should be impossible.");
    }
    const auto id = new_frame_id(NonNull(*obj), task);
    if (symbol) {
      cs_ref.frames.push_back(sym::Frame{task, depth, id, i.as_void(), symbol});
    } else {
      auto obj = find_obj_by_pc(frame_pc);
      auto min_sym = obj->search_minsym_fn_info(frame_pc);
      if (min_sym) {
        cs_ref.frames.push_back(sym::Frame{task, depth, id, i.as_void(), min_sym});
      } else {
        DLOG("mdb", "[stackframe]: WARNING, no frame info for pc {}", i.as_void());
        cs_ref.frames.push_back(sym::Frame{task, depth, id, i.as_void(), nullptr});
      }
    }
  }
  cs_ref.dirty = false;
  return cs_ref;
}

ObjectFile *
TraceeController::find_obj_by_pc(AddrPtr addr) const noexcept
{
  for (auto obj : object_files) {
    if (obj->address_bounds.contains(addr))
      return obj;
  }
  return nullptr;
}

sym::FunctionSymbol *
TraceeController::find_fn_by_pc(AddrPtr addr, ObjectFile **foundIn = nullptr) const noexcept
{
  const auto obj = find_obj_by_pc(addr);
  if (obj == nullptr)
    return {};

  if (foundIn)
    *foundIn = obj;
  auto cus_matching_addr = obj->get_cus_from_pc(addr);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  for (auto cu : cus_matching_addr) {
    for (auto &src : obj->source_units()) {
      if (cu == src.get_dwarf_unit()) {
        if (auto fn = src.get_fn_by_pc(addr); fn)
          return fn;
      }
    }
  }
  return nullptr;
}

std::optional<std::filesystem::path>
TraceeController::get_source(std::string_view name) noexcept
{
  for (auto obj : object_files) {
    auto source = obj->get_source_file(name);
    if (source) {
      return source->full_path;
    }
  }
  return std::nullopt;
}

const ElfSection *
TraceeController::get_text_section(AddrPtr addr) const noexcept
{
  const auto obj = find_obj_by_pc(addr);
  if (obj) {
    const auto text = obj->parsed_elf->get_section(".text");
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
  all_stopped_observer.send_notifications();
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