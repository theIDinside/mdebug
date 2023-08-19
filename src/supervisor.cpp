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
#include "symbolication/cu.h"
#include "symbolication/cu_file.h"
#include "symbolication/dwarf_expressions.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/elf.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/lnp.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tracer.h"
#include "utils/logger.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <link.h>
#include <linux/auxvec.h>
#include <memory_resource>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

template <typename T> using Set = std::unordered_set<T>;

TraceeController::TraceeController(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify,
                                   TargetSession session, bool open_mem_fd) noexcept
    : task_leader{process_space_id}, object_files{}, main_executable(nullptr), threads{}, bps(process_space_id),
      tracee_r_debug(nullptr), shared_objects(), var_refs(), spin_lock{}, interpreter_base{}, entry{},
      session(session), is_in_user_ptrace_stop(false), ptracestop_handler(new ptracestop::StopHandler{this}),
      unwinders(), null_unwinder(new sym::Unwinder{nullptr})
{
  awaiter_thread = std::make_unique<AwaiterThread>(awaiter_notify, process_space_id);
  threads.push_back(TaskInfo{process_space_id});
  threads.back().initialize();
  if (open_mem_fd) {
    const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
    procfs_memfd = ScopedFd::open(procfs_path, O_RDWR);
  }
}

bool
TraceeController::reopen_memfd() noexcept
{
  const auto procfs_path = fmt::format("/proc/{}/task/{}/mem", task_leader, task_leader);
  procfs_memfd = ScopedFd::open(procfs_path, O_RDWR);
  return procfs_memfd.is_open();
}

struct ProbeInfo
{
  AddrPtr address;
  std::string name;
};

static std::vector<ProbeInfo>
parse_stapsdt_note(const ElfSection *section) noexcept
{
  std::vector<ProbeInfo> probes;
  DwarfBinaryReader reader{section};
  std::set<std::string_view> required_probes{{"map_complete", "reloc_complete", "unmap_complete"}};
  // stapsdt, location 8 bytes, base 8 bytes, semaphore 8 bytes, desc=string of N bytes, then more bytes we don't
  // care for

  while (reader.has_more() && required_probes.size() > 0) {
    reader.read_value<u32>();
    reader.read_value<u32>();
    reader.read_value<u32>();
    const auto stapsdt = reader.read_string();
    ASSERT(stapsdt == "stapsdt", "Failed to see 'stapsdt' deliminator; saw {}", stapsdt);
    const auto ptr = reader.read_value<u64>();
    const auto base = reader.read_value<u64>();
    const auto semaphore = reader.read_value<u64>();
    const auto provider = reader.read_string();
    ASSERT(provider == "rtld", "Supported provider is rtld, got {}", provider);
    const auto probe_name = reader.read_string();
    const auto description = reader.read_string();
    if (reader.bytes_read() % 4 != 0)
      reader.skip(4 - reader.bytes_read() % 4);
    if (required_probes.contains(probe_name)) {
      DLOG("mdb", "adding {} probe at {}", probe_name, ptr);
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
  auto int_path = interpreter_path(object_files.front()->parsed_elf->get_section(".interp"));
  auto tmp_objfile = mmap_objectfile(int_path);
  ASSERT(tmp_objfile != nullptr, "Failed to mmap the loader binary");
  Elf::parse_elf_owned_by_obj(tmp_objfile, interpreter_base.value());
  tmp_objfile->parsed_elf->parse_min_symbols(AddrPtr{interpreter_base.value()});
  const auto system_tap_sec = tmp_objfile->parsed_elf->get_section(".note.stapsdt");
  ASSERT(system_tap_sec->file_offset == 0x35118, "Unexpected file offset for .note.stapsdt");
  const auto probes = parse_stapsdt_note(system_tap_sec);
  tracee_r_debug = get_rdebug_state(tmp_objfile);
  DLOG("mdb", "_r_debug found at {}", tracee_r_debug);
  for (const auto symbol_name : LOADER_SYMBOL_NAMES) {
    if (tmp_objfile->minimal_fn_symbols.contains(symbol_name)) {
      const auto addr = tmp_objfile->minimal_fn_symbols[symbol_name].address;
      DLOG("mdb", "Setting ld breakpoint at {}", addr);
      set_tracer_bp(addr.as<u64>(), BpType{.shared_object_load = true});
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
      r_debug_extended rdebug_ext = read_type(next);
    } else {
      break;
    }
  }
  DLOG("mdb", "[so event] new={}", new_sos);

  // do simple parsing first, then collect to do extensive processing in parallell
  std::vector<SharedObject::SoId> sos;
  for (auto i = 0; i < new_sos; ++i) {
    auto so = shared_objects.get_so(new_so_ids[i]);
    const auto so_of = mmap_objectfile(so->path);
    so->objfile = so_of;
    if (so_of) {
      register_object_file(so_of, false, so->elf_vma_addr_diff);
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
    if (so->objfile != nullptr && so->objfile->parsed_elf->get_section(".debug_info") != nullptr) {
      so->objfile->line_table_headers = parse_lnp_headers(so->objfile->parsed_elf);
      so->objfile->line_tables.reserve(so->objfile->line_table_headers.size());
      for (auto &lth : so->objfile->line_table_headers) {
        so->objfile->line_tables.push_back({});
        lth.set_linetable_storage(&so->objfile->line_tables.back());
      }
      CompilationUnitBuilder cu_builder{so->objfile};
      auto total = cu_builder.build_cu_headers();
      const auto total_sz = total.size();
      for (const auto &hdr : total) {
        ASSERT(so->objfile != nullptr, "Objfile is null!");
        auto proc = prepare_cu_processing(so->objfile, hdr, this);
        auto die = proc->read_dies();
        proc->process_compile_unit_die(die.release());
      }
    }
    Tracer::Instance->post_event(new ui::dap::ModuleEvent{"new", so});
  }
}

ScopedFd &
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
  return waitpid_block(tid).transform([this](auto &&wpid) {
    TaskWaitResult wait{};
    wait.waited_pid = wpid.tid;
    task_wait_emplace(wpid.status, &wait);
    return wait;
  });
}

void
TraceeController::new_task(Tid tid, bool ui_update) noexcept
{
  VERIFY(tid != 0, "Invalid tid {}", tid);
  auto evt = new ui::dap::OutputEvent{
      "console"sv, fmt::format("Task ({}) {} created (task leader: {})", threads.size() + 1, tid, task_leader)};
  Tracer::Instance->post_event(evt);
  threads.push_back(TaskInfo{tid});

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
  for (auto &t : threads) {
    if (t.can_continue()) {
      if (t.bstat) {
        auto bp = bps.get_by_id(t.bstat->bp_id);
        DLOG("mdb", "Stepping over bp {} ({}) for task {}", bp->id, bp->address, t.tid);
        bp->disable(t.tid);
        int stat;
        VERIFY(-1 != ptrace(PTRACE_SINGLESTEP, t.tid, 1, 0),
               "Single step over user breakpoint boundary failed: {}", strerror(errno));
        waitpid(t.tid, &stat, 0);
        t.set_dirty();
        bp->enable(t.tid);
        if (type == RunType::Step)
          continue;
      }
      t.resume(type);
    }
  }
  ptracestop_handler->can_resume();
}

void
TraceeController::stop_all() noexcept
{
  DLOG("mdb", "Stopping all threads")
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
  }
}

void
TraceeController::reap_task(TaskInfo *task) noexcept
{
  auto it = std::ranges::find_if(threads, [&](auto &t) { return t.tid == task->tid; });
  VERIFY(it != std::end(threads), "Could not find Task with pid {}", task->tid);
  task->exited = true;
  Tracer::Instance->thread_exited({.pid = task_leader, .tid = it->tid}, it->wait_status.data.exit_signal);
  if (task->tid == task_leader) {
    awaiter_thread->set_process_exited();
  }
}

TaskInfo *
TraceeController::register_task_waited(TaskWaitResult wait) noexcept
{
  ASSERT(has_task(wait.waited_pid), "Target did not contain task {}", wait.waited_pid);
  auto task = get_task(wait.waited_pid);
  task->set_taskwait(wait);
  task->tracer_stopped = true;
  return task;
}

AddrPtr
TraceeController::get_caching_pc(TaskInfo *t) noexcept
{
  if (t->rip_dirty) {
    t->cache_registers();
    return t->registers->rip;
  } else {
    return t->registers->rip;
  }
}

void
TraceeController::set_pc(TaskInfo *t, AddrPtr addr) noexcept
{
  DLOG("mdb", "Setting pc to {}", addr);
  constexpr auto rip_offset = offsetof(user_regs_struct, rip);
  VERIFY(ptrace(PTRACE_POKEUSER, t->tid, rip_offset, addr.get()) != -1, "Failed to set RIP register");
  t->registers->rip = addr;
  t->rip_dirty = false;
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
  bps.insert(address.as_void(), original_byte, BpType{.address = true});
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
  DLOG("mdb", "Installing tracer breakpoint at {}", addr);
  u8 bkpt = 0xcc;
  const auto original_byte = read_type_safe(addr.as<u8>());
  ASSERT(original_byte.has_value(), "Failed to read byte at {}", addr);
  write(addr.as<u8>(), bkpt);
  bps.insert(addr.as_void(), *original_byte, type);
  return true;
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
  }
  DLOG("mdb", "Found {} matching symbols for {}", matching_symbols.size(), function_name);
  for (const auto &sym : matching_symbols) {
    DLOG("mdb", "Setting breakpoint @ {}", sym.address);
    constexpr u64 bkpt = 0xcc;
    if (bps.contains(sym.address)) {
      auto bp = bps.get(sym.address);
      bp->bp_type.add_setting({.function = true});
      bps.fn_breakpoint_names[bp->id] = function_name;
    } else {
      auto ins_byte = write_bp_byte(sym.address);
      bps.insert(sym.address, ins_byte, BpType{.function = true});
      auto &bp = bps.breakpoints.back();
      bps.fn_breakpoint_names[bp.id] = function_name;
    }
  }
}

void
TraceeController::set_source_breakpoints(std::string_view src,
                                         std::vector<SourceBreakpointDescriptor> &&descs) noexcept
{
  logging::get_logging()->log("mdb",
                              fmt::format("Setting breakpoints in {}; requested {} bps", src, descs.size()));
  for (const auto obj : object_files) {
    const auto f_it = find(obj->m_full_cu, [src](const CompilationUnitFile &cu) { return cu.fullpath() == src; });
    if (f_it != std::end(obj->m_full_cu)) {
      for (auto &&desc : descs) {
        // naming it, because who the fuck knows if C++ decides to copy it behind our backs.
        const auto &lt = f_it->line_table();
        for (const auto &lte : lt) {
          if (desc.line == lte.line && lte.column == desc.column.value_or(lte.column)) {
            if (!bps.contains(lte.pc)) {
              logging::get_logging()->log("mdb", fmt::format("Setting breakpoint at {}", lte.pc));
              u8 original_byte = write_bp_byte(lte.pc);
              bps.insert(lte.pc, original_byte, BpType{.source = true});
              const auto &bp = bps.breakpoints.back();
              bps.source_breakpoints[bp.id] = std::move(desc);
              break;
            } else {
              auto bp = bps.get(lte.pc);
              bp->bp_type.source = true;
            }
          }
        }
      }
    } else {
      logging::get_logging()->log("mdb", fmt::format("Could not find file!!!", src, descs.size()));
    }
  }
  logging::get_logging()->log("mdb", fmt::format("Total breakpoints {}", bps.breakpoints.size()));
}

void
TraceeController::emit_stopped_at_breakpoint(LWP lwp, u32 bp_id) noexcept
{
  auto evt =
      new ui::dap::StoppedEvent{ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", true};
  evt->bp_ids.push_back(bp_id);
  Tracer::Instance->post_event(evt);
}

void
TraceeController::emit_stepped_stop(LWP lwp) noexcept
{
  Tracer::Instance->post_event(
      new ui::dap::StoppedEvent{ui::dap::StoppedReason::Step, "Stepping finished", lwp.tid, {}, "", true});
}

void
TraceeController::emit_signal_event(LWP lwp, int signal) noexcept
{
  Tracer::Instance->post_event(new ui::dap::StoppedEvent{
      ui::dap::StoppedReason::Exception, fmt::format("Signalled {}", signal), lwp.tid, {}, "", true});
}

void
TraceeController::reset_addr_breakpoints(std::vector<AddrPtr> addresses) noexcept
{
  bps.clear(this, BpType{.address = true});
  for (auto addr : addresses) {
    set_addr_breakpoint(addr.as<u64>());
  }
}

void
TraceeController::reset_fn_breakpoints(std::vector<std::string_view> fn_names) noexcept
{
  bps.clear(this, BpType{.function = true});
  bps.fn_breakpoint_names.clear();
  for (auto fn_name : fn_names) {
    set_fn_breakpoint(fn_name);
  }
}

void
TraceeController::reset_source_breakpoints(std::string_view source_filepath,
                                           std::vector<SourceBreakpointDescriptor> &&bps) noexcept
{
  auto type = BpType{0};
  type.source = true;
  this->bps.clear(this, type);
  set_source_breakpoints(source_filepath, std::move(bps));
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
  if (is_running()) {
    stop_all();
  }
  return ::kill(task_leader, SIGKILL) == 0;
}

bool
TraceeController::detach() noexcept
{
  if (is_running()) {
    stop_all();
  }
  std::vector<std::pair<Tid, int>> errs;
  for (auto t : threads) {
    const auto res = ptrace(PTRACE_DETACH, t.tid, 0, 0);
    if (res == -1)
      errs.push_back(std::make_pair(t.tid, errno));
  }

  // todo(simon): construct a way to let this information bubble up to caller
  return errs.empty();
}

void
TraceeController::restore_default_handler() noexcept
{
  ptracestop_handler->restore_default();
}

void
TraceeController::task_wait_emplace(int status, TaskWaitResult *wait) noexcept
{
  ASSERT(wait != nullptr, "wait param must not be null");
  if (WIFSTOPPED(status)) {
    task_wait_emplace_stopped(status, wait);
    return;
  }

  if (WIFEXITED(status)) {
    task_wait_emplace_exited(status, wait);
    return;
  }

  if (WIFSIGNALED(status)) {
    task_wait_emplace_signalled(status, wait);
    return;
  }
}

void
TraceeController::task_wait_emplace_stopped(int status, TaskWaitResult *wait) noexcept
{
  using enum WaitStatusKind;
  if (IS_SYSCALL_SIGTRAP(WSTOPSIG(status))) {
    PtraceSyscallInfo info;
    constexpr auto size = sizeof(PtraceSyscallInfo);
    PTRACE_OR_PANIC(PTRACE_GET_SYSCALL_INFO, wait->waited_pid, size, &info);
    if (info.is_entry()) {
      wait->ws.ws = SyscallEntry;
    } else {
      wait->ws.ws = SyscallExit;
    }
    return;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_CLONE)) {
    wait->ws.ws = Cloned;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_EXEC)) {
    wait->ws.ws = Execed;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_EXIT)) {
    wait->ws.ws = Exited;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_FORK)) {
    wait->ws.ws = Forked;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_VFORK)) {
    wait->ws.ws = VForked;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_VFORK_DONE)) {
    wait->ws.ws = VForkDone;
  } else if (WSTOPSIG(status) == SIGTRAP) {
    wait->ws.ws = Stopped;
  } else if (WSTOPSIG(status) == SIGSTOP) {
    wait->ws.ws = Stopped;
  } else {
    wait->ws.ws = Stopped;
    fmt::println("SOME OTHER STOP FOR {}. WSTOPSIG: {}", wait->waited_pid, WSTOPSIG(status));
    sleep(1);
  }
}

void
TraceeController::task_wait_emplace_signalled(int status, TaskWaitResult *wait) noexcept
{
  wait->ws.ws = WaitStatusKind::Signalled;
  wait->ws.data.signal = WTERMSIG(status);
}

void
TraceeController::task_wait_emplace_exited(int status, TaskWaitResult *wait) noexcept
{
  wait->ws.ws = WaitStatusKind::Exited;
  wait->ws.data.exit_signal = WEXITSTATUS(status);
}

void
TraceeController::process_exec(TaskInfo *t) noexcept
{
  DLOG("mdb", "Processing EXEC for {}", t->tid);
  reopen_memfd();
  t->cache_registers();
  read_auxv(t);
}

Tid
TraceeController::process_clone(TaskInfo *t) noexcept
{
  DLOG("mdb", "Processing CLONE for {}", t->tid);
  const auto stopped_tid = t->tid;
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  t->cache_registers();
  const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(*t->registers);
  const auto res = read_type(ptr);
  // Nasty way to get PID, but, in doing so, we also get stack size + stack location for new thread
  auto np = read_type(TPtr<pid_t>{res.parent_tid});
#ifdef MDB_DEBUG
  long new_pid = 0;
  PTRACE_OR_PANIC(PTRACE_GETEVENTMSG, t->tid, 0, &new_pid);
  ASSERT(np == new_pid, "Inconsistent pid values retrieved, expected {} but got {}", np, new_pid);
#endif
  if (!has_task(np)) {
    new_task(np, true);
  }
  // by this point, the task has cloned _and_ it's continuable because the parent has been told
  // that "hey, we're ok". Why on earth a pre-finished clone can be waited on, I will never know.
  get_task(np)->initialize();
  // task backing storage may have re-allocated and invalidated this pointer.
  t = get_task(stopped_tid);
  set_task_vm_info(np, TaskVMInfo::from_clone_args(res));
  return np;
}

BpEvent
TraceeController::process_stopped(TaskInfo *t) noexcept
{
  const auto pc = get_caching_pc(t);
  DLOG("mdb", "Processing stopped for {} at {}", t->tid, AddrPtr{t->registers->rip});
  const auto prev_pc_byte = offset(pc, -1);
  if (auto bp = bps.get(prev_pc_byte); bp != nullptr) {
    if (t->bstat && t->bstat->stepped_over) {
      t->bstat = std::nullopt;
      return BpEvent{BpEventType::None, {nullptr}};
    }
    DLOG("mdb", "{} Hit breakpoint {} at {}: {}", t->tid, bp->id, prev_pc_byte, bp->type());
    set_pc(t, prev_pc_byte);
    t->add_bpstat(bp);
    return BpEvent{bp->event_type(), {.bp = bp}};
  }
  t->bstat = std::nullopt;
  return BpEvent{BpEventType::None, {nullptr}};
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
  object_files.push_back(obj);
  if (obj->minimal_fn_symbols.empty()) {
    obj->parsed_elf->parse_min_symbols(base_vma.value_or(0));
  }
  if (is_main_executable)
    main_executable = obj;

  auto unwinder = sym::parse_eh(obj, obj->parsed_elf->get_section(".eh_frame"), base_vma.value_or(0));
  const auto section = obj->parsed_elf->get_section(".debug_frame");
  if (section) {
    DLOG("mdb", ".debug_frame section found; parsing DWARF CFI section");
    sym::parse_dwarf_eh(unwinder, section, -1);
  }

  unwinders.push_back(unwinder);
  // todo(simon): optimization possible; insert in a sorted fashion instead.
  std::sort(unwinders.begin(), unwinders.end(), [](auto a, auto b) {
    return a->addr_range.low < b->addr_range.low && a->addr_range.high < b->addr_range.high;
  });
}

struct AuxvPair
{
  u64 key, value;
};

void
TraceeController::read_auxv(TaskInfo *task)
{
  ASSERT(task->wait_status.ws == WaitStatusKind::Execed,
         "Reading AUXV using this function does not make sense if's not *right* after an EXEC");
  TPtr<i64> stack_ptr = task->registers->rsp;
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
  ScopedFd f = ScopedFd::open_read_only(p);
  char buf[16];
  std::memset(buf, 0, 16);
  ::read(f, buf, 16);
  auto name = std::string{buf};
  if (name.ends_with("\n")) {
    name.pop_back();
  }
  return name;
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
TraceeController::add_file(ObjectFile *obj, CompilationUnitFile &&file) noexcept
{
  {
    LockGuard guard{spin_lock};
    if (file.low_high_pc().is_valid()) {
      constexpr auto file_sorter_by_addresses = [](CompilationUnitFile &f, const AddressRange &range) noexcept {
        const auto faddr_rng = f.low_high_pc();
        return range.high > faddr_rng.low;
      };
      auto it_pos = std::lower_bound(obj->m_full_cu.begin(), obj->m_full_cu.end(), file.low_high_pc(),
                                     file_sorter_by_addresses);
      obj->m_full_cu.insert(it_pos, std::move(file));
    } else {
      obj->m_partial_units.push_back({});
    }
  }
  auto evt = new ui::dap::OutputEvent{"console"sv, fmt::format("Adding file {}", file)};
  Tracer::Instance->post_event(evt);
}

void
TraceeController::reaped_events() noexcept
{
  DLOG("mdb", "Reaped events");
  awaiter_thread->reaped_events();
}

void
TraceeController::notify_self() noexcept
{
  DLOG("mdb", "Notifying self...");
  awaiter_thread->get_notifier().notify();
}

/** Called after an exec has been processed and we've set up the necessary data structures
  to manage it.*/
void
TraceeController::start_awaiter_thread() noexcept
{
  awaiter_thread->start_awaiter_thread();
}

sym::Frame
TraceeController::current_frame(TaskInfo *task) noexcept
{
  task->cache_registers();
  auto symbol = find_fn_by_pc(task->registers->rip);
  if (symbol)
    return sym::Frame{
        .rip = task->registers->rip,
        .symbol = symbol->fn_sym,
        .cu_file = symbol->cu_file,
        .level = 0,
        .type = sym::FrameType::Full,
    };
  else
    return sym::Frame{
        .rip = task->registers->rip,
        .symbol = nullptr,
        .cu_file = nullptr,
        .level = 0,
        .type = sym::FrameType::Full,
    };
}

sym::Unwinder *
TraceeController::get_unwinder_from_pc(AddrPtr pc) noexcept
{
  for (auto unwinder : unwinders) {
    if (unwinder->addr_range.contains(pc)) {
      return unwinder;
    }
  }
  return null_unwinder;
}

const std::vector<AddrPtr> &
TraceeController::dwarf_unwind_callstack(TaskInfo *task, CallStackRequest req) noexcept
{
  return task->return_addresses(this, req);
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
    auto cu = get_cu_from_pc(task->registers->rip);
    if (cu) {
      const auto [a, b] = cu->get_range(frame_pcs.front().as_void());
      if (b && b->prologue_end)
        inside_prologue = true;
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
        if (cu->may_contain(AddrPtr{ret_val_a})) {
          frame_pcs.insert(frame_pcs.begin() + 1, ret_val_a);
          resolved = true;
        }
      }

      if (!resolved) {
        auto ret_val_b = read_type_safe(offset(ret_addr, 8)).value_or(0);
        if (!resolved && ret_val_b != 0) {
          if (cu->may_contain(AddrPtr{ret_val_b})) {
            frame_pcs.insert(frame_pcs.begin() + 1, ret_val_b);
          }
        }
      }
    }
    return task->call_stack->pcs;
  }
}

int
TraceeController::new_frame_id(TaskInfo *task) noexcept
{
  using VR = ui::dap::VariablesReference;
  const auto res = next_var_ref;
  var_refs[res] = VR{.thread_id = task->tid, .frame_id = res, .parent = 0, .type = ui::dap::EntityType::Frame};
  ++next_var_ref;
  return res;
}

int
TraceeController::new_scope_id(const sym::Frame *frame) noexcept
{
  using VR = ui::dap::VariablesReference;
  const auto res = next_var_ref;
  const auto vr = var_refs[frame->frame_id];
  var_refs[res] = VR{.thread_id = vr.thread_id,
                     .frame_id = frame->frame_id,
                     .parent = frame->frame_id,
                     .type = ui::dap::EntityType::Scope};
  ++next_var_ref;
  return res;
}

int
TraceeController::new_var_id(int parent_id) noexcept
{
  using VR = ui::dap::VariablesReference;
  const auto res = next_var_ref;
  const auto vr = var_refs[parent_id];
  var_refs[res] = VR{.thread_id = vr.thread_id,
                     .frame_id = vr.frame_id,
                     .parent = parent_id,
                     .type = ui::dap::EntityType::Variable};
  ++next_var_ref;
  return res;
}

void
TraceeController::reset_variable_references() noexcept
{
  var_refs.clear();
}

sym::CallStack &
TraceeController::build_callframe_stack(TaskInfo *task, CallStackRequest req) noexcept
{
  DLOG("mdb", "stacktrace for {}", task->tid);
  task->cache_registers();
  auto &cs = *task->call_stack;
  cs.frames.clear();
  auto level = 1;
  auto frame_pcs = task->return_addresses(this, req);
  const auto levels = frame_pcs.size();
  for (auto i = frame_pcs.begin(); i != frame_pcs.end(); i++) {
    auto symbol = find_fn_by_pc(i->as_void());
    const auto id = new_frame_id(task);
    if (symbol)
      cs.frames.push_back(sym::Frame{
          .rip = i->as_void(),
          .symbol = symbol->fn_sym,
          .cu_file = symbol->cu_file,
          .level = static_cast<int>(levels - level),
          .type = sym::FrameType::Full,
          .frame_id = id,
      });
    else {
      cs.frames.push_back(sym::Frame{
          .rip = i->as_void(),
          .symbol = nullptr,
          .cu_file = nullptr,
          .level = static_cast<int>(levels - level),
          .type = sym::FrameType::Unknown,
          .frame_id = id,
      });
    }
    ++level;
  }
  task->call_stack->dirty = false;
  return *task->call_stack;
}

ObjectFile *
TraceeController::find_obj_by_pc(AddrPtr addr) const noexcept
{
  for (const auto obj : object_files) {
    if (obj->address_bounds.contains(addr))
      return obj;
  }
  return nullptr;
}

std::optional<SearchFnSymResult>
TraceeController::find_fn_by_pc(AddrPtr addr) const noexcept
{
  const auto obj = find_obj_by_pc(addr);
  for (auto &f : obj->m_full_cu) {
    if (f.may_contain(addr)) {
      const auto fn = f.find_subprogram(addr);
      if (fn != nullptr) {
        return SearchFnSymResult{.fn_sym = fn, .cu_file = &f};
      }
    }
  }
  DLOG("mdb", "couldn't find fn for pc {}", addr);
  return std::nullopt;
}

std::optional<std::string_view>
TraceeController::get_source(std::string_view name) noexcept
{
  for (auto obj : object_files) {
    for (const auto &f : obj->m_full_cu) {
      if (f.name() == name) {
        return f.name();
      }
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

const CompilationUnitFile *
TraceeController::get_cu_from_pc(AddrPtr address) const noexcept
{
  const auto obj = find_obj_by_pc(address);
  if (auto it = find(obj->m_full_cu, [addr = address](const auto &f) { return f.may_contain(addr); });
      it != std::cend(obj->m_full_cu)) {
    return it.base();
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
  return std::array<S, 3>{S{"Arguments", "arguments", new_scope_id(f)}, S{"Locals", "locals", new_scope_id(f)},
                          S{"Registers", "registers", new_scope_id(f)}};
}

const sym::Frame *
TraceeController::frame(int frame_id) noexcept
{
  const auto frame_ref_info = var_refs[frame_id];
  auto task = get_task(frame_ref_info.thread_id);
  return task->call_stack->get_frame(frame_id);
}

#pragma GCC diagnostic pop

// 0x405e6b