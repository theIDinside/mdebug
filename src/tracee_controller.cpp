#include "tracee_controller.h"
#include "breakpoint.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "notify_pipe.h"
#include "ptrace.h"
#include "ptracestop_handlers.h"
#include "symbolication/callstack.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/objfile.h"
#include "symbolication/type.h"
#include "task.h"
#include "tracer.h"
#include "utils/logger.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <linux/auxvec.h>
#include <memory_resource>
#include <optional>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>

template <typename T> using Set = std::unordered_set<T>;

TraceeController::TraceeController(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify,
                                   TargetSession session, bool open_mem_fd) noexcept
    : task_leader{process_space_id}, object_files{}, threads{}, bps(process_space_id),
      stop_on_clone(false), spin_lock{}, m_files{}, interpreter_base{}, entry{}, session(session),
      is_in_user_ptrace_stop(false), ptracestop_handler(new ptracestop::StopHandler{this})
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
  DLOG("mdb", "TraceeController::resume_target");
  // Single-step over breakpoints that were hit, then re-enable them.
  if (!bps.bpstats.empty()) {
    for (auto bp_stat : bps.bpstats) {
      auto bp = bps.get_by_id(bp_stat.bp_id);
      DLOG("mdb", "Stepping over bp {} ({}) for task {}", bp->id, bp->address, bp_stat.tid);
      bp->disable(bp_stat.tid);
      int stat;
      VERIFY(-1 != ptrace(PTRACE_SINGLESTEP, bp_stat.tid, 1, 0),
             "Single step over user breakpoint boundary failed: {}", strerror(errno));
      waitpid(bp_stat.tid, &stat, 0);
      auto task = get_task(bp_stat.tid);
      task->set_dirty();
      cache_registers(task);
      ASSERT(AddrPtr{task->registers->rip} != bp->address, "Failed to single step over breakpoint at {}",
             bp->address);
      bps.enable_breakpoint(bp_stat.bp_id);
    }
  }

  bps.clear_breakpoint_stats();
  for (auto &t : threads) {
    if (t.can_continue()) {
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
    if (!t.user_stopped) {
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

bool
TraceeController::should_stop_on_clone() noexcept
{
  return false;
  // return stop_on_clone;
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
    cache_registers(t);
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
TraceeController::cache_registers(TaskInfo *task) noexcept
{
  if (task->cache_dirty) {
    PTRACE_OR_PANIC(PTRACE_GETREGS, task->tid, nullptr, task->registers);
    task->cache_dirty = false;
    task->rip_dirty = false;
  }
}

void
TraceeController::set_addr_breakpoint(TraceePointer<u64> address) noexcept
{
  if (bps.contains(address)) {
    auto bp = bps.get(address.as<void>());
    bp->bp_type.address = true;
    return;
  }

  constexpr u64 bkpt = 0xcc;
  auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, address.get(), nullptr);
  u8 original_byte = static_cast<u8>(read_value & 0xff);
  u64 installed_bp = ((read_value & ~0xff) | bkpt);
  ptrace(PTRACE_POKEDATA, task_leader, address.get(), installed_bp);

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
  constexpr u64 bkpt = 0xcc;
  auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, addr.get(), nullptr);
  u8 original_byte = static_cast<u8>(read_value & 0xff);
  u64 installed_bp = ((read_value & ~0xff) | bkpt);
  ptrace(PTRACE_POKEDATA, task_leader, addr.get(), installed_bp);

  bps.insert(addr.as_void(), original_byte, type);
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
    if (auto s = obj->get_minsymbol(function_name); s.has_value()) {
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
      auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, sym.address.get(), nullptr);
      u8 ins_byte = static_cast<u8>(read_value & 0xff);
      u64 installed_bp = ((read_value & ~0xff) | bkpt);
      ptrace(PTRACE_POKEDATA, task_leader, sym.address.get(), installed_bp);
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
  auto f = find(m_files, [src](const CompilationUnitFile &cu) { return cu.fullpath() == src; });
  if (f != std::end(m_files)) {
    for (auto &&desc : descs) {
      // naming it, because who the fuck knows if C++ decides to copy it behind our backs.
      const auto &lt = f->line_table();
      for (const auto &lte : lt) {
        if (desc.line == lte.line && lte.column == desc.column.value_or(lte.column)) {
          if (!bps.contains(lte.pc)) {
            logging::get_logging()->log("mdb", fmt::format("Setting breakpoint at {}", lte.pc));
            constexpr u64 bkpt = 0xcc;
            auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, lte.pc, nullptr);
            u8 original_byte = static_cast<u8>(read_value & 0xff);
            u64 installed_bp = ((read_value & ~0xff) | bkpt);
            ptrace(PTRACE_POKEDATA, task_leader, lte.pc, installed_bp);
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
  this->bps.clear(this, BpType{.source = true});
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
  cache_registers(t);
  read_auxv(t);
}

Tid
TraceeController::process_clone(TaskInfo *t) noexcept
{
  DLOG("mdb", "Processing CLONE for {}", t->tid);
  const auto stopped_tid = t->tid;
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  cache_registers(t);
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
  DLOG("mdb", "Processing stopped for {}", t->tid);
  const auto pc = get_caching_pc(t);
  const auto prev_pc_byte = offset(pc, -1);
  if (auto bp = bps.get(prev_pc_byte); bp != nullptr) {
    auto bpstat = find(bps.bpstats, [t](auto &bpstat) { return bpstat.tid == t->tid; });
    if (bpstat != std::end(bps.bpstats) && bpstat->stepped_over) {
      bps.bpstats.erase(bpstat);
      return BpEvent{BpEventType::None, {nullptr}};
    }
    DLOG("mdb", "{} Hit breakpoint {} at {}", t->tid, bp->id, prev_pc_byte);
    set_pc(t, prev_pc_byte);
    bps.add_bpstat_for(t, bp);
    return BpEvent{bp->event_type(), {.bp = bp}};
  }
  std::erase_if(bps.bpstats, [t](auto &bpstat) { return bpstat.tid == t->tid && bpstat.stepped_over; });
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
TraceeController::register_object_file(ObjectFile *obj) noexcept
{
  object_files.push_back(obj);
  if (obj->minimal_symbols.empty()) {
    obj->parsed_elf->parse_min_symbols();
  }
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

utils::StaticVector<u8>::own_ptr
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

void
TraceeController::add_file(CompilationUnitFile &&file) noexcept
{
  {
    LockGuard guard{spin_lock};
    constexpr auto file_sorter_by_addresses = [](CompilationUnitFile &f, const AddressRange &range) noexcept {
      const auto faddr_rng = f.low_high_pc();
      return range.high > faddr_rng.low;
    };
    auto it_pos = std::lower_bound(m_files.begin(), m_files.end(), file.low_high_pc(), file_sorter_by_addresses);
    m_files.insert(it_pos, std::move(file));
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
  cache_registers(task);
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

sym::CallStack &
TraceeController::build_callframe_stack(TaskInfo *task) noexcept
{
  DLOG("mdb", "stacktrace for {}", task->tid);
  cache_registers(task);
  auto &cs = *task->call_stack;
  cs.frames.clear();
  auto level = 1;
  auto &frame_pcs = unwind_callstack(task);
  const auto levels = frame_pcs.size();
  for (auto i = frame_pcs.begin(); i != frame_pcs.end(); i++) {
    auto symbol = find_fn_by_pc(i->as_void());
    if (symbol)
      cs.frames.push_back(sym::Frame{
          .rip = i->as_void(),
          .symbol = symbol->fn_sym,
          .cu_file = symbol->cu_file,
          .level = static_cast<int>(levels - level),
          .type = sym::FrameType::Full,

      });
    else {
      cs.frames.push_back(sym::Frame{
          .rip = i->as_void(),
          .symbol = nullptr,
          .cu_file = nullptr,
          .level = static_cast<int>(levels - level),
          .type = sym::FrameType::Unknown,
      });
    }
    ++level;
  }
  task->call_stack->dirty = false;
  return *task->call_stack;
}

std::optional<SearchFnSymResult>
TraceeController::find_fn_by_pc(AddrPtr addr) const noexcept
{
  for (auto &f : m_files) {
    if (f.may_contain(addr)) {
      const auto fn = f.find_subprogram(addr);
      if (fn != nullptr) {
        return SearchFnSymResult{.fn_sym = fn, .cu_file = &f};
      }
    }
  }
  return std::nullopt;
}

std::optional<std::string_view>
TraceeController::get_source(std::string_view name) noexcept
{
  for (const auto &f : m_files) {
    if (f.name() == name) {
      return f.name();
    }
  }
  return std::nullopt;
}

u8 *
TraceeController::get_in_text_section(AddrPtr vma) const noexcept
{
  for (const auto obj : object_files) {
    const auto sec = obj->parsed_elf->get_section(".text");
    TPtr<void> relo_addr{sec->address};
    auto offset = vma - relo_addr;
    if (offset < sec->size()) {
      return sec->m_section_ptr + offset;
    }
  }
  return nullptr;
}

ElfSection *
TraceeController::get_text_section(AddrPtr addr) const noexcept
{
  for (const auto of : object_files) {
    auto text = of->parsed_elf->get_section(".text");
    if (text->contains_relo_addr(addr))
      return text;
  }
  return nullptr;
}

std::optional<u64>
TraceeController::cu_file_from_pc(AddrPtr address) const noexcept
{
  const auto first =
      std::find_if(m_files.begin(), m_files.end(), [address](const auto &f) { return f.may_contain(address); });
  if (first != std::cend(m_files)) {
    return std::distance(std::cbegin(m_files), first);
  } else {
    return std::nullopt;
  }
}

const CompilationUnitFile *
TraceeController::get_cu_from_pc(AddrPtr address) const noexcept
{
  if (auto it = find(m_files, [addr = address](const auto &f) { return f.may_contain(addr); });
      it != std::cend(m_files)) {
    return &*it;
  }
  return nullptr;
}

const std::vector<CompilationUnitFile> &
TraceeController::cu_files() const noexcept
{
  return m_files;
}

ptracestop::StopHandler *
TraceeController::stop_handler() const noexcept
{
  return ptracestop_handler;
}