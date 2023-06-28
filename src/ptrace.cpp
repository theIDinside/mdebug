#include "ptrace.h"
#include "common.h"
#include "task.h"
#include <cstdlib>
#include <source_location>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

std::string_view
request_name(__ptrace_request req)
{
  switch (req) {
  case PTRACE_TRACEME:
    return "PTRACE_TRACEME";
  case PTRACE_PEEKTEXT:
    return "PTRACE_PEEKTEXT";
  case PTRACE_PEEKDATA:
    return "PTRACE_PEEKDATA";
  case PTRACE_PEEKUSER:
    return "PTRACE_PEEKUSER";
  case PTRACE_POKETEXT:
    return "PTRACE_POKETEXT";
  case PTRACE_POKEDATA:
    return "PTRACE_POKEDATA";
  case PTRACE_POKEUSER:
    return "PTRACE_POKEUSER";
  case PTRACE_CONT:
    return "PTRACE_CONT";
  case PTRACE_KILL:
    return "PTRACE_KILL";
  case PTRACE_SINGLESTEP:
    return "PTRACE_SINGLESTEP";
  case PTRACE_GETREGS:
    return "PTRACE_GETREGS";
  case PTRACE_SETREGS:
    return "PTRACE_SETREGS";
  case PTRACE_GETFPREGS:
    return "PTRACE_GETFPREGS";
  case PTRACE_SETFPREGS:
    return "PTRACE_SETFPREGS";
  case PTRACE_ATTACH:
    return "PTRACE_ATTACH";
  case PTRACE_DETACH:
    return "PTRACE_DETACH";
  case PTRACE_GETFPXREGS:
    return "PTRACE_GETFPXREGS";
  case PTRACE_SETFPXREGS:
    return "PTRACE_SETFPXREGS";
  case PTRACE_SYSCALL:
    return "PTRACE_SYSCALL";
  case PTRACE_GET_THREAD_AREA:
    return "PTRACE_GET_THREAD_AREA";
  case PTRACE_SET_THREAD_AREA:
    return "PTRACE_SET_THREAD_AREA";
  case PTRACE_ARCH_PRCTL:
    return "PTRACE_ARCH_PRCTL";
  case PTRACE_SYSEMU:
    return "PTRACE_SYSEMU";
  case PTRACE_SYSEMU_SINGLESTEP:
    return "PTRACE_SYSEMU_SINGLESTEP";
  case PTRACE_SINGLEBLOCK:
    return "PTRACE_SINGLEBLOCK";
  case PTRACE_SETOPTIONS:
    return "PTRACE_SETOPTIONS";
  case PTRACE_GETEVENTMSG:
    return "PTRACE_GETEVENTMSG";
  case PTRACE_GETSIGINFO:
    return "PTRACE_GETSIGINFO";
  case PTRACE_SETSIGINFO:
    return "PTRACE_SETSIGINFO";
  case PTRACE_GETREGSET:
    return "PTRACE_GETREGSET";
  case PTRACE_SETREGSET:
    return "PTRACE_SETREGSET";
  case PTRACE_SEIZE:
    return "PTRACE_SEIZE";
  case PTRACE_INTERRUPT:
    return "PTRACE_INTERRUPT";
  case PTRACE_LISTEN:
    return "PTRACE_LISTEN";
  case PTRACE_PEEKSIGINFO:
    return "PTRACE_PEEKSIGINFO";
  case PTRACE_GETSIGMASK:
    return "PTRACE_GETSIGMASK";
  case PTRACE_SETSIGMASK:
    return "PTRACE_SETSIGMASK";
  case PTRACE_SECCOMP_GET_FILTER:
    return "PTRACE_SECCOMP_GET_FILTER";
  case PTRACE_SECCOMP_GET_METADATA:
    return "PTRACE_SECCOMP_GET_METADATA";
  case PTRACE_GET_SYSCALL_INFO:
    return "PTRACE_GET_SYSCALL_INFO";
  case PTRACE_GET_RSEQ_CONFIGURATION:
    return "PTRACE_GET_RSEQ_CONFIGURATION";
  }
}

void
new_target_set_options(pid_t pid)
{
  const auto options = (PTRACE_O_TRACESYSGOOD /*| PTRACE_O_TRACEVFORKDONE */ | PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE);
  if (-1 == ptrace(PTRACE_SETOPTIONS, pid, 0, options)) {
    sleep(1);
    if (-1 == ptrace(PTRACE_SETOPTIONS, pid, 0, options)) {
      PANIC(fmt::format("Failed to set PTRACE options for {}: {}", pid, strerror(errno)));
    }
  }
}

// PtraceSyscallInfo::PtraceSyscallInfo(__ptrace_syscall_info info) noexcept : m_info(info) {}

std::uintptr_t
PtraceSyscallInfo::stack_ptr() const noexcept
{
  return m_info.stack_pointer;
}
std::uintptr_t
PtraceSyscallInfo::ip() const noexcept
{
  return m_info.instruction_pointer;
}
SyscallStop
PtraceSyscallInfo::syscall_stop() const noexcept
{
#ifdef MDB_DEBUG
  if (!is_entry() && !is_exit()) {
    PANIC("Sanitized value is invalid.");
  }
#endif
  return (SyscallStop)m_info.op;
}
bool
PtraceSyscallInfo::is_entry() const noexcept
{
  return m_info.op == PTRACE_SYSCALL_INFO_ENTRY;
}
bool
PtraceSyscallInfo::is_exit() const noexcept
{
  return m_info.op == PTRACE_SYSCALL_INFO_EXIT;
}
bool
PtraceSyscallInfo::is_seccomp() const noexcept
{
  return m_info.op == PTRACE_SYSCALL_INFO_SECCOMP;
}

bool
PtraceSyscallInfo::is_none() const noexcept
{
  return m_info.op == PTRACE_SYSCALL_INFO_NONE;
}

void
ptrace_panic(__ptrace_request req, pid_t pid, const std::source_location &loc)
{
  panic(fmt::format("{} FAILED for {}", request_name(req), pid), loc, 3);
}

SyscallArguments::SyscallArguments(const user_regs_struct &regs) : regs(&regs) {}

#ifdef MDB_DEBUG
void
SyscallArguments::debug_print(bool flush, bool pretty)
{
  using enum SysRegister;
  if (pretty) {
    fmt::print("{{\n  arg1 0x{:x} ({}),\n  arg2 0x{:x} ({}),\n  arg3 0x{:x} ({}),\n  arg4 0x{:x} ({}),\n  arg5 "
               "0x{:x} ({}),\n  arg6 0x{:x} ({})\n}}",
               arg_n<1>(), arg<RDI>(), arg_n<2>(), arg<RSI>(), arg_n<3>(), arg<RDX>(), arg_n<4>(), arg<R10>(),
               arg_n<5>(), arg<R8>(), arg_n<6>(), arg<R9>());
  } else {
    fmt::print("{{ arg1 0x{:x}, arg2 0x{:x}, arg3 0x{:x}, arg4 0x{:x}, arg5 0x{:x}, arg6 0x{:x} }}", arg_n<1>(),
               arg_n<2>(), arg_n<3>(), arg_n<4>(), arg_n<5>(), arg_n<6>());
  }
  if (flush)
    fmt::println("");
}
#else

#endif


constexpr auto
IS_SYSCALL_SIGTRAP(auto stopsig)
{
  return stopsig == (SIGTRAP | 0x80);
}

constexpr auto
IS_TRACE_CLONE(auto stopsig) {
  return stopsig>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8));
}

constexpr auto
IS_TRACE_EXEC(auto stopsig) {
  return stopsig>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8));
}

constexpr auto
IS_TRACE_EVENT(auto stopsig, auto ptrace_event) {
  return stopsig>>8 == (SIGTRAP | (ptrace_event << 8));
}

WaitStatus
from_register(u64 syscall_number) {
  using enum WaitStatus;
  if(syscall_number == SYS_clone || syscall_number == SYS_clone3) {
    return Cloned;
  }
  if(syscall_number == SYS_execve || syscall_number == SYS_execveat) {
    return Execed;
  }
  return WaitStatus::Stopped;
}

constexpr void
task_wait_emplace_stopped(int status, TaskWaitResult *wait)
{
  using enum WaitStatus;
  if (IS_SYSCALL_SIGTRAP(WSTOPSIG(status))) {
      PtraceSyscallInfo info;
      constexpr auto size = sizeof(PtraceSyscallInfo);
      PTRACE_OR_PANIC(PTRACE_GET_SYSCALL_INFO, wait->waited_pid, size, &info);
    if(info.is_entry()) {
      wait->ws = SyscallEntry;
    } else {
      wait->ws = SyscallExit;
    }
    return;
  } else if(IS_TRACE_EVENT(status, PTRACE_EVENT_CLONE)) {
    wait->ws = Cloned;
  } else if(IS_TRACE_EVENT(status, PTRACE_EVENT_EXEC)) {
    wait->ws = Execed;
  } else if(IS_TRACE_EVENT(status, PTRACE_EVENT_EXIT)) {
    wait->ws = Exited;
  } else if(IS_TRACE_EVENT(status, PTRACE_EVENT_FORK)) {
    wait->ws = Forked;
  } else if(IS_TRACE_EVENT(status, PTRACE_EVENT_VFORK)) {
    wait->ws = VForked;
  } else if(IS_TRACE_EVENT(status, PTRACE_EVENT_VFORK_DONE)) {
    wait->ws = VForkDone;
  }
}

void
task_wait_emplace_signalled(int status, TaskWaitResult *wait)
{
  wait->ws = WaitStatus::Signalled;
  wait->data.signal = WTERMSIG(status);
}

void
task_wait_emplace_exited(int status, TaskWaitResult *wait)
{
  wait->ws = WaitStatus::Exited;
  wait->data.exit_signal = WEXITSTATUS(status);
}

void
task_wait_emplace(int status, TaskWaitResult *wait)
{
  ASSERT(wait != nullptr, "wait param must not be null");

  ptrace(PTRACE_GETREGS, wait->waited_pid, nullptr, &wait->registers);

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