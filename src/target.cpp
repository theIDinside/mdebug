#include "target.h"
#include "breakpoint.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "notify_pipe.h"
#include "ptrace.h"
#include "symbolication/callstack.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/objfile.h"
#include "symbolication/type.h"
#include "task.h"
#include "tracer.h"
#include "utils/logger.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <linux/auxvec.h>
#include <optional>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

Target::Target(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify, TargetSession session,
               bool open_mem_fd) noexcept
    : task_leader{process_space_id}, object_files{}, threads{}, user_brkpts(process_space_id),
      stop_on_clone(false), spin_lock{}, m_files{}, interpreter_base{}, entry{}, register_cache(),
      session(session), is_in_user_ptrace_stop(false)
{
  awaiter_thread = std::make_unique<AwaiterThread>(awaiter_notify, process_space_id);
  threads.push_back(TaskInfo{process_space_id});
  threads.back().initialize();
  frame_cache.push_back(sym::CallStack{.tid = threads.back().tid, .frames = {}});
  if (open_mem_fd) {
    const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
    procfs_memfd = ScopedFd::open(procfs_path, O_RDWR);
  }
}

bool
Target::reopen_memfd() noexcept
{
  const auto procfs_path = fmt::format("/proc/{}/task/{}/mem", task_leader, task_leader);
  procfs_memfd = ScopedFd::open(procfs_path, O_RDWR);
  return procfs_memfd.is_open();
}

ScopedFd &
Target::mem_fd() noexcept
{
  return procfs_memfd;
}

TaskInfo *
Target::get_task(pid_t tid) noexcept
{
  for (auto &t : threads) {
    if (t.tid == tid)
      return &t;
  }
  return &(*threads.begin());
}

std::optional<TaskWaitResult>
Target::wait_pid(TaskInfo *requested_task) noexcept
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
Target::new_task(Tid tid, bool ui_update) noexcept
{
  VERIFY(tid != 0, "Invalid tid {}", tid);
  auto evt = new ui::dap::OutputEvent{
      "console"sv, fmt::format("Task ({}) {} created (task leader: {})", threads.size() + 1, tid, task_leader)};
  Tracer::Instance->post_event(evt);
  threads.push_back(TaskInfo{tid});
  frame_cache.push_back(sym::CallStack{.tid = tid, .frames = {}});

  ASSERT(std::ranges::all_of(threads, [](TaskInfo &t) { return t.tid != 0; }),
         "Fucking hidden move construction fucked a Task in the ass and gave it 0 as pid");
  if (ui_update) {
    const auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Started, tid};
    Tracer::Instance->post_event(evt);
  }
}

bool
Target::has_task(Tid tid) noexcept
{
  for (const auto &task : threads) {
    if (task.tid == tid)
      return true;
  }
  return false;
}

void
Target::resume_target(RunType type) noexcept
{
  // Single-step over breakpoints that were hit, then re-enable them.
  if (!user_brkpts.task_bp_stats.empty()) {
    for (auto bp_stat : user_brkpts.task_bp_stats) {
      auto bp = user_brkpts.get_by_id(bp_stat.bp_id);
      bp->disable(bp_stat.task.tid);
      int stat;
      VERIFY(-1 != ptrace(PTRACE_SINGLESTEP, bp_stat.task.tid, 1, 0),
             "Single step over user breakpoint boundary failed: {}", strerror(errno));
      waitpid(bp_stat.task.tid, &stat, 0);
      ASSERT(TPtr<void>{cache_registers(bp_stat.task.tid).rip} != bp->address,
             "Failed to single step over breakpoint at {}", bp->address);
      user_brkpts.enable_breakpoint(bp_stat.bp_id);
    }
  }
  user_brkpts.clear_breakpoint_stats();
  for (auto &t : threads) {
    if (t.can_continue()) {
      t.set_running(type);
    }
  }
}

void
Target::stop_all() noexcept
{
  ::kill(task_leader, SIGSTOP);
  for (auto &t : threads) {
    if (!t.stopped) {
      t.set_stop();
      t.ptrace_stop = true;
    }
  }
}

bool
Target::should_stop_on_clone() noexcept
{
  return false;
  // return stop_on_clone;
}

ActionOnEvent
Target::handle_stopped_for(TaskInfo *task) noexcept
{
  auto &task_register = register_cache[task->tid];
  const auto current_pc = TPtr<void>{task_register.rip};
  const auto prev_pc_byte = current_pc - 1;
  if (this->user_brkpts.contains(prev_pc_byte)) {
    set_pc(task, prev_pc_byte);
    emit_stopped_at_breakpoint({.pid = task_leader, .tid = task->tid}, (current_pc - 1));
    return ActionOnEvent::StopTracee;
  } else {
    // No action needs taking, restart `task`
    return ActionOnEvent::ShouldContinue;
  }
}

void
Target::reap_task(TaskInfo *task) noexcept
{
  auto it = std::ranges::find_if(threads, [&](auto &t) { return t.tid == task->tid; });
  VERIFY(it != std::end(threads), "Could not find Task with pid {}", task->tid);
  Tracer::Instance->thread_exited({.pid = task_leader, .tid = it->tid}, it->wait_status->data.exit_signal);
  if (task->tid == task_leader) {
    awaiter_thread->set_process_exited();
  }
  threads.erase(it);
}

void
Target::register_task_waited(TaskWaitResult wait) noexcept
{
  ASSERT(has_task(wait.waited_pid), "Target did not contain task {}", wait.waited_pid);
  auto task = get_task(wait.waited_pid);
  ASSERT(task != nullptr, "No task found with tid {}", wait.waited_pid);
  task->set_taskwait(wait);
}

void
Target::set_pc(TaskInfo *t, TPtr<void> addr) noexcept
{
  const auto rip_offset = offsetof(user_regs_struct, rip);
  VERIFY(ptrace(PTRACE_POKEUSER, t->tid, rip_offset, addr.get()) != -1, "Failed to set RIP register");
  register_cache[t->tid].rip = addr;
}

void
Target::set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept
{
  ASSERT(has_task(tid), "Unknown task {}", tid);
  task_vm_infos[tid] = vm_info;
}

const user_regs_struct &
Target::cache_registers(Tid tid) noexcept
{
  auto &registers = register_cache[tid];
  PTRACE_OR_PANIC(PTRACE_GETREGS, tid, nullptr, &registers);
  return registers;
}

void
Target::set_addr_breakpoint(TraceePointer<u64> address) noexcept
{
  if (user_brkpts.contains(address))
    return;

  constexpr u64 bkpt = 0xcc;
  auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, address.get(), nullptr);
  u8 original_byte = static_cast<u8>(read_value & 0xff);
  u64 installed_bp = ((read_value & ~0xff) | bkpt);
  ptrace(PTRACE_POKEDATA, task_leader, address.get(), installed_bp);

  user_brkpts.insert(address.as<void>(), original_byte, BreakpointType::AddressBreakpoint);
}

void
Target::set_fn_breakpoint(std::string_view function_name) noexcept
{
  for (const auto &[id, name] : user_brkpts.fn_breakpoint_names) {
    if (name == function_name)
      return;
  }

  std::vector<MinSymbol> matching_symbols;
  for (ObjectFile *obj : object_files) {
    if (auto s = obj->get_minsymbol(function_name); s.has_value()) {
      matching_symbols.push_back(*s);
    }
  }

  for (const auto &sym : matching_symbols) {
    constexpr u64 bkpt = 0xcc;
    auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, sym.address.get(), nullptr);
    u8 ins_byte = static_cast<u8>(read_value & 0xff);
    u64 installed_bp = ((read_value & ~0xff) | bkpt);
    ptrace(PTRACE_POKEDATA, task_leader, sym.address.get(), installed_bp);
    user_brkpts.insert(sym.address, ins_byte, BreakpointType::FunctionBreakpoint);
    auto &bp = user_brkpts.breakpoints.back();
    user_brkpts.fn_breakpoint_names[bp.bp_id] = function_name;
  }
}

void
Target::set_source_breakpoints(std::string_view src, std::vector<SourceBreakpointDescriptor> &&descs) noexcept
{
  logging::get_logging()->log("mdb",
                              fmt::format("Setting breakpoints in {}; requested {} bps", src, descs.size()));
  auto f = find(m_files, [src](const CompilationUnitFile &cu) { return cu.fullpath() == src; });
  if (f != std::end(m_files)) {
    for (auto &&desc : descs) {
      logging::get_logging()->log(
          "mdb", fmt::format("Setting at {}:{}", desc.line,
                             desc.column.transform([](auto v) { return std::to_string(v); }).value_or("None")));
      for (const auto &lte : f->line_table()) {
        if (desc.line == lte.line && lte.column == desc.column.value_or(lte.column)) {
          if (!user_brkpts.contains(lte.pc)) {
            constexpr u64 bkpt = 0xcc;
            auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, lte.pc, nullptr);
            u8 original_byte = static_cast<u8>(read_value & 0xff);
            u64 installed_bp = ((read_value & ~0xff) | bkpt);
            ptrace(PTRACE_POKEDATA, task_leader, lte.pc, installed_bp);
            user_brkpts.insert(lte.pc, original_byte, BreakpointType::SourceBreakpoint);
            const auto &bp = user_brkpts.breakpoints.back();
            user_brkpts.source_breakpoints[bp.bp_id] = std::move(desc);
            break;
          }
        }
      }
    }
  } else {
    logging::get_logging()->log("mdb", fmt::format("Could not find file!!!", src, descs.size()));
  }
}

void
Target::emit_stopped_at_breakpoint(LWP lwp, TPtr<void> bp_addr)
{
  auto bp = user_brkpts.get(bp_addr);
  user_brkpts.task_bp_stats.push_back({.task = *get_task(lwp.tid), .bp_id = bp->bp_id});
  bp->times_hit++;
  auto evt =
      new ui::dap::StoppedEvent{ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", true};
  evt->bp_ids.push_back(bp->bp_id);
  Tracer::Instance->post_event(evt);
}

void
Target::reset_addr_breakpoints(std::vector<TPtr<void>> addresses) noexcept
{
  user_brkpts.clear(this, BreakpointType::AddressBreakpoint);
  for (auto addr : addresses) {
    set_addr_breakpoint(addr.as<u64>());
  }
}

void
Target::reset_fn_breakpoints(std::vector<std::string_view> fn_names) noexcept
{
  user_brkpts.clear(this, BreakpointType::FunctionBreakpoint);
  user_brkpts.fn_breakpoint_names.clear();
  for (auto fn_name : fn_names) {
    set_fn_breakpoint(fn_name);
  }
}

void
Target::reset_source_breakpoints(std::string_view source_filepath,
                                 std::vector<SourceBreakpointDescriptor> &&bps) noexcept
{
  std::erase_if(user_brkpts.breakpoints, [&bpm = user_brkpts, path = source_filepath](Breakpoint &bp) {
    if (bp.type == BreakpointType::SourceBreakpoint) {
      if (bpm.source_breakpoints[bp.bp_id].source_file.compare(path) == 0) {
        bpm.source_breakpoints.erase(bp.bp_id);
        if (bp.enabled)
          bp.disable(bpm.address_space_tid);
        return true;
      }
    }
    return false;
  });
  set_source_breakpoints(source_filepath, std::move(bps));
}

bool
Target::kill() noexcept
{
  bool done = ptrace(PTRACE_KILL, task_leader, nullptr, nullptr) != -1;
  bool threads_done = false;
  for (const auto &t : threads) {
    threads_done = threads_done && (ptrace(PTRACE_KILL, t.tid, nullptr, nullptr) != -1);
  }
  return done || threads_done;
}

bool
Target::terminate_gracefully() noexcept
{
  if (is_running()) {
    stop_all();
  }
  return ::kill(task_leader, SIGKILL) == 0;
}

bool
Target::detach() noexcept
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
Target::task_wait_emplace(int status, TaskWaitResult *wait) noexcept
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
Target::task_wait_emplace_stopped(int status, TaskWaitResult *wait) noexcept
{
  using enum WaitStatus;
  if (IS_SYSCALL_SIGTRAP(WSTOPSIG(status))) {
    PtraceSyscallInfo info;
    constexpr auto size = sizeof(PtraceSyscallInfo);
    PTRACE_OR_PANIC(PTRACE_GET_SYSCALL_INFO, wait->waited_pid, size, &info);
    if (info.is_entry()) {
      wait->ws = SyscallEntry;
    } else {
      wait->ws = SyscallExit;
    }
    return;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_CLONE)) {
    wait->ws = Cloned;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_EXEC)) {
    wait->ws = Execed;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_EXIT)) {
    wait->ws = Exited;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_FORK)) {
    wait->ws = Forked;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_VFORK)) {
    wait->ws = VForked;
  } else if (IS_TRACE_EVENT(status, PTRACE_EVENT_VFORK_DONE)) {
    wait->ws = VForkDone;
  } else if (WSTOPSIG(status) == SIGTRAP) {
    wait->ws = Stopped;
  } else if (WSTOPSIG(status) == SIGSTOP) {
    wait->ws = Stopped;
  } else {
    wait->ws = Stopped;
    fmt::println("SOME OTHER STOP FOR {}. WSTOPSIG: {}", wait->waited_pid, WSTOPSIG(status));
    sleep(1);
  }
}

void
Target::task_wait_emplace_signalled(int status, TaskWaitResult *wait) noexcept
{
  wait->ws = WaitStatus::Signalled;
  wait->data.signal = WTERMSIG(status);
}

void
Target::task_wait_emplace_exited(int status, TaskWaitResult *wait) noexcept
{
  wait->ws = WaitStatus::Exited;
  wait->data.exit_signal = WEXITSTATUS(status);
}

bool
Target::execution_not_ended() const noexcept
{
  return !threads.empty();
}

bool
Target::is_running() const noexcept
{
  return std::any_of(threads.cbegin(), threads.cend(), [](const TaskInfo &t) { return !t.is_stopped(); });
}

bool
BreakpointMap::insert(TraceePointer<void> addr, u8 ins_byte, BreakpointType type) noexcept
{
  if (contains(addr))
    return false;
  breakpoints.push_back(Breakpoint{addr, ins_byte, bp_id_counter++, type});
  return true;
}

void
BreakpointMap::clear(Target *target, BreakpointType type) noexcept
{
  std::erase_if(breakpoints, [t = this, target, type](Breakpoint &bp) {
    if (bp.type == type) {
      if (bp.enabled)
        bp.disable(target->task_leader);
      switch (bp.type) {
      case BreakpointType::SourceBreakpoint:
        t->source_breakpoints.erase(bp.bp_id);
        break;
      case BreakpointType::FunctionBreakpoint:
        t->fn_breakpoint_names.erase(bp.bp_id);
        break;
      case BreakpointType::AddressBreakpoint:
        break;
      }
      return true;
    } else {
      return false;
    }
  });
}

void
BreakpointMap::clear_breakpoint_stats() noexcept
{
  task_bp_stats.clear();
}

void
BreakpointMap::disable_breakpoint(u16 id) noexcept
{
  auto bp = get_by_id(id);
  bp->disable(address_space_tid);
}

void
BreakpointMap::enable_breakpoint(u16 id) noexcept
{
  auto bp = get_by_id(id);
  bp->enable(address_space_tid);
}

Breakpoint *
BreakpointMap::get_by_id(u32 id) noexcept
{
  auto it = std::find_if(breakpoints.begin(), breakpoints.end(), [&](const auto &bp) { return bp.bp_id == id; });
  ASSERT(it != end(breakpoints), "Expected to find a breakpoint with id {}", id);
  return &(*it);
}
Breakpoint *
BreakpointMap::get(TraceePointer<void> addr) noexcept
{
  auto iter = find(breakpoints, [addr](auto &bp) { return bp.address == addr; });
  if (iter != std::cend(breakpoints))
    return &(*iter);
  else
    return nullptr;
}

// Debug Symbols Related Logic
void
Target::register_object_file(ObjectFile *obj) noexcept
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
Target::read_auxv(TaskWaitResult &wait)
{
  ASSERT(wait.ws == WaitStatus::Execed,
         "Reading AUXV using this function does not make sense if's not *right* after an EXEC");
  auto task = get_task(wait.waited_pid);
  auto &registers = register_cache[task->tid];
  TPtr<i64> stack_ptr = registers.rsp;
  i64 argc = read_type(stack_ptr);

  stack_ptr += argc + 1;
  ASSERT(read_type(stack_ptr) == 0, "Expected null terminator after argv at {}", stack_ptr);
  stack_ptr++;
  auto envp = stack_ptr.as<const char *>();
  // we're at the envp now, that pointer list is also terminated by a nullptr
  while (read_type(envp) != nullptr) {
    envp++;
  }
  // We should now be at Auxilliary Vector Table (see `man getauxval` for info, we're interested in the interpreter
  // base address)

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
Target::session_type() const noexcept
{
  return session;
}

std::string
Target::get_thread_name(Tid tid) const noexcept
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
Target::read_to_vector(TraceePointer<void> addr, u64 bytes) noexcept
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
Target::add_file(CompilationUnitFile &&file) noexcept
{
  {
    LockGuard guard{spin_lock};
    m_files.push_back(file);
  }
  auto evt = new ui::dap::OutputEvent{"console"sv, fmt::format("Adding file {}", file)};
  Tracer::Instance->post_event(evt);
}

void
Target::reaped_events() noexcept
{
  awaiter_thread->reaped_events();
}

/** Called after an exec has been processed and we've set up the necessary data structures
  to manage it.*/
void
Target::start_awaiter_thread() noexcept
{
  awaiter_thread->start_awaiter_thread();
}

sym::CallStack &
Target::build_callframe_stack(const TaskInfo *task) noexcept
{
  std::vector<TPtr<std::uintptr_t>> bps;
  auto bp = register_cache[task->tid].rbp;
  bps.push_back(bp);
  while (true) {
    TPtr<std::uintptr_t> bp_addr = bps.back();
    const auto prev_bp = read_type_safe(bp_addr);
    if (prev_bp) {
      if (*prev_bp == 0x1) {
        break;
      }
      bps.push_back(*prev_bp);
    } else
      break;
  }

  std::vector<TPtr<std::uintptr_t>> rsps;
  rsps.reserve(bps.size());
  rsps.push_back(register_cache[task->tid].rip);
  for (auto bp_it = bps.begin(); bp_it != bps.end(); ++bp_it) {
    const auto ret_addr = read_type<TPtr<std::uintptr_t>>({bp_it->offset(8)});
    rsps.push_back(ret_addr);
  }

  for (auto &cs : frame_cache) {
    if (cs.tid == task->tid) {
      // N.B! N.B! N.B! todo(simon): this probably has room for LOTS of optimization
      //  instead of throwing it all away _every step, every stop_.
      cs.frames.clear();
      for (auto i = rsps.begin(); i != rsps.end(); i++) {
        auto symbol = find_fn_by_pc(i->as_void());
        if (symbol)
          cs.frames.push_back(sym::Frame{.start = symbol->fn_sym->start,
                                         .end = symbol->fn_sym->end,
                                         .rip = i->as_void(),
                                         .fn_name = symbol->fn_sym->name,
                                         .cu_file = symbol->cu_file,
                                         .type = sym::FrameType::Full});
        else {
          cs.frames.push_back(sym::Frame{.start = nullptr,
                                         .end = nullptr,
                                         .rip = i->as_void(),
                                         .fn_name = "unknown",
                                         .cu_file = nullptr,
                                         .type = sym::FrameType::Unknown});
        }
      }
      return cs;
    }
  }
  PANIC(fmt::format("Failed to find call stack for {}", task->tid));
}

std::optional<SearchFnSymResult>
Target::find_fn_by_pc(TPtr<void> addr) noexcept
{
  for (auto &f : m_files) {
    if (f.may_contain(addr)) {
      auto fn = f.find_subprogram(addr);
      if (fn != nullptr) {
        return SearchFnSymResult{.fn_sym = fn, .cu_file = &f};
      }
    }
  }
  return {};
}

std::optional<std::string_view>
Target::get_source(std::string_view name) noexcept
{
  for (const auto &f : m_files) {
    if (f.name() == name) {
      return f.name();
    }
  }
  return std::nullopt;
}