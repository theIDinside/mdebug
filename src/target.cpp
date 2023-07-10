#include "target.h"
#include "breakpoint.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "interface/dap/protocol.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "ptrace.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tracer.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <linux/auxvec.h>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
Target::Target(pid_t process_space_id, bool open_mem_fd) noexcept
    : task_leader{process_space_id}, object_files{}, threads{}, bkpt_map({.bp_id_counter = 1, .breakpoints = {}}),
      stop_on_clone(false), spin_lock{}, m_files{}, m_types{}, interpreter_base{}, entry{}, register_cache()
{
  threads.push_back(TaskInfo{process_space_id});
  threads.back().initialize();
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
  return nullptr;
}

std::optional<TaskWaitResult>
Target::wait_pid(TaskInfo *requested_task) noexcept
{
  const auto tid = requested_task == nullptr ? -1 : requested_task->tid;
  return waitpid_nonblock(tid).transform([this](auto &&wpid) {
    TaskWaitResult wait{};
    wait.waited_pid = wpid.tid;
    task_wait_emplace(wpid.status, &wait);
    return wait;
  });
}

void
Target::new_task(Tid tid) noexcept
{
  VERIFY(tid != 0, "Invalid tid {}", tid);
  if constexpr (MDB_DEBUG) {
    auto evt = new ui::dap::OutputEvent{
        "console"sv, fmt::format("Task ({}) {} created (task leader: {})", threads.size() + 1, tid, task_leader)};
    Tracer::Instance->post_event(evt);
  }
  threads.push_back(TaskInfo{tid});

  ASSERT(std::ranges::all_of(threads, [](TaskInfo &t) { return t.tid != 0; }),
         "Fucking hidden move construction fucked a Task in the ass and gave it 0 as pid");
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
Target::set_all_running(RunType type) noexcept
{
  for (auto &t : threads) {
    if (t.can_continue()) {
      t.set_running(type);
    }
  }
}

void
Target::stop_all() noexcept
{
  kill(task_leader, SIGSTOP);
  for (auto &t : threads) {
    if (!t.stopped) {
      t.set_stop();
      t.stopped_by_tracer = true;
    }
  }
}

bool
Target::should_stop_on_clone() noexcept
{
  return stop_on_clone;
}

ActionOnEvent
Target::handle_stopped_for(TaskInfo *task) noexcept
{
  auto &task_register = register_cache[task->tid];
  const auto current_pc = TPtr<void>{task_register.rip};
  if (this->bkpt_map.contains(current_pc - 1)) {
    emit_breakpoint_event((current_pc - 1));
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
Target::set_breakpoint(TraceePointer<u64> address) noexcept
{
  if (bkpt_map.contains(address))
    return;

  constexpr u64 bkpt = 0xcc;
  auto read_value = ptrace(PTRACE_PEEKDATA, task_leader, address.get(), nullptr);
  u8 ins_byte = static_cast<u8>(read_value & 0xff);
  u64 installed_bp = ((read_value & ~0xff) | bkpt);
  ptrace(PTRACE_POKEDATA, task_leader, address.get(), installed_bp);

  bkpt_map.insert(address.as<void>(), ins_byte);
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
    fmt::println("SOME OTHER STOP FOR {}", wait->waited_pid);
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
Target::running() const noexcept
{
  return !threads.empty();
}

bool
BreakpointMap::insert(TraceePointer<void> addr, u8 ins_byte) noexcept
{
  if (contains(addr))
    return false;
  breakpoints[addr.get()] = Breakpoint{ins_byte, bp_id_counter++};
  return true;
}

Breakpoint *
BreakpointMap::get(u32 id) noexcept
{
  auto it = std::find_if(breakpoints.begin(), breakpoints.end(),
                         [&](const auto &kvp) { return kvp.second.bp_id == id; });
  if (it == std::end(breakpoints))
    return nullptr;

  return &(it->second);
}
Breakpoint *
BreakpointMap::get(TraceePointer<void> addr) noexcept
{
  if (!contains(addr))
    return nullptr;
  else
    return &breakpoints[addr.get()];
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

void
Target::emit_breakpoint_event(TPtr<void> bp_addr)
{
  auto bp = bkpt_map.get(bp_addr);
  bp->times_hit++;
  auto evt = new ui::dap::StoppedEvent{ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", {}};
  evt->bp_ids.push_back(bp->bp_id);
  Tracer::Instance->post_event(evt);
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
Target::add_type(Type type) noexcept
{
  LockGuard guard{spin_lock};
  m_types[type.name] = type;
}