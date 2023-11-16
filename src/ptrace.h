#pragma once
#include "common.h"
#include <source_location>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

struct TaskWaitResult;
struct TaskInfo;

enum class WaitStatusKind : u16
{
#define ITEM(IT, Value) IT = Value,
#include "./defs/waitstatus.def"
#undef ITEM
};

constexpr std::string_view
to_str(WaitStatusKind ws)
{
  switch (ws) {
#define ITEM(IT, Value)                                                                                           \
  case WaitStatusKind::IT:                                                                                        \
    return #IT;
#include "./defs/waitstatus.def"
#undef ITEM
  }
}

struct WaitStatus
{
  WaitStatusKind ws;
  union
  {
    int exit_code;
    int signal;
  };
};

struct TaskWaitResult
{
  Tid tid;
  WaitStatus ws;
};

std::string_view request_name(__ptrace_request req);

void new_target_set_options(pid_t pid);

void ptrace_panic(__ptrace_request req, pid_t pid, const std::source_location &loc);

template <typename Addr = std::nullptr_t, typename Data = std::nullptr_t>
constexpr void
ptrace_or_panic(auto req, pid_t pid, Addr addr, Data data, std::source_location &loc)
{
  if (-1 == ptrace((__ptrace_request)req, pid, addr, data)) {
    ptrace_panic((__ptrace_request)req, pid, loc);
  }
}

#define COMBINE1(X, Y) X##Y // helper macro
#define COMBINE(X, Y) COMBINE1(X, Y)

#define LOC_NAME COMBINE(loc, __LINE__)

#define PTRACE_OR_PANIC(req, pid, addr, data)                                                                     \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    ptrace_or_panic(req, pid, addr, data, loc);                                                                   \
  }

enum class SyscallStop : u8
{
  Entry = PTRACE_SYSCALL_INFO_ENTRY,
  Exit = PTRACE_SYSCALL_INFO_EXIT,
};

// The equivalent of "extension-functions". It's terrible. but it is what C++/C offers us. You just have to learn
// to live with it.
class PtraceSyscallInfo
{
public:
  std::uintptr_t stack_ptr() const noexcept;
  std::uintptr_t ip() const noexcept;
  SyscallStop syscall_stop() const noexcept;
  bool is_entry() const noexcept;
  bool is_exit() const noexcept;
  bool is_seccomp() const noexcept;
  bool is_none() const noexcept;

  __ptrace_syscall_info m_info;
};

enum SysRegister : size_t
{
  RDI = 1,
  RSI = 2,
  RDX = 3,
  R10 = 4,
  R8 = 5,
  R9 = 6,
  Return = 7,
  ReturnValue2 = 8,
};

struct SyscallArguments
{

  SyscallArguments(const user_regs_struct &regs);

#ifdef MDB_DEBUG
  void debug_print(bool flush, bool pretty);
#else

#endif

  template <SysRegister Arg>
  constexpr u64
  arg() const noexcept
  {
    return arg_helper<(size_t)Arg>();
  }

  template <size_t Arg>
  constexpr u64
  arg_n() const noexcept
  {
    return arg_helper<Arg>();
  }

  template <SysRegister Arg>
  constexpr u64
  retval() const noexcept
  {
    if constexpr (Arg == 7) {
      return regs->rax;
    } else if constexpr (Arg == 8) {
      return regs->rdx;
    } else {
      static_assert(always_false_i<Arg>, "Invalid return value register");
    }
  }

  template <size_t Arg>
  constexpr u64
  arg_helper() const noexcept
  {
    if constexpr (Arg == 1) {
      return regs->rdi;
    } else if constexpr (Arg == 2) {
      return regs->rsi;
    } else if constexpr (Arg == 3) {
      return regs->rdx;
    } else if constexpr (Arg == 4) {
      return regs->r10;
    } else if constexpr (Arg == 5) {
      return regs->r8;
    } else if constexpr (Arg == 6) {
      return regs->r9;
    } else {
      static_assert(always_false_i<Arg>, "Invalid syscall argument");
    }
  }

  const user_regs_struct *regs;
};

template <size_t Arg>
constexpr u64
arg_helper(const user_regs_struct &regs) noexcept
{
  if constexpr (Arg == 1) {
    return regs.rdi;
  } else if constexpr (Arg == 2) {
    return regs.rsi;
  } else if constexpr (Arg == 3) {
    return regs.rdx;
  } else if constexpr (Arg == 4) {
    return regs.r10;
  } else if constexpr (Arg == 5) {
    return regs.r8;
  } else if constexpr (Arg == 6) {
    return regs.r9;
  } else {
    static_assert(always_false_i<Arg>, "Invalid syscall argument");
  }
}

template <SysRegister Arg>
constexpr u64
sys_arg(const user_regs_struct &regs) noexcept
{
  return arg_helper<(size_t)Arg>(regs);
}

template <size_t Arg>
constexpr u64
sys_arg_n(const user_regs_struct &regs) noexcept
{
  return arg_helper<Arg>(regs);
}

template <SysRegister Arg>
constexpr u64
sys_retval(const user_regs_struct &regs) noexcept
{
  if constexpr (Arg == 7) {
    return regs.rax;
  } else if constexpr (Arg == 8) {
    return regs.rdx;
  } else {
    static_assert(always_false_i<Arg>, "Invalid return value register");
  }
}

constexpr auto
IS_SYSCALL_SIGTRAP(auto stopsig) noexcept -> bool
{
  return stopsig == (SIGTRAP | 0x80);
}

constexpr auto
IS_TRACE_CLONE(auto stopsig) noexcept -> bool
{
  return stopsig >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8));
}

constexpr auto
IS_TRACE_EXEC(auto stopsig) noexcept -> bool
{
  return stopsig >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8));
}

constexpr auto
IS_TRACE_EVENT(auto stopsig, auto ptrace_event) noexcept -> bool
{
  return stopsig >> 8 == (SIGTRAP | (ptrace_event << 8));
}

TaskWaitResult process_status(Tid tid, int status) noexcept;