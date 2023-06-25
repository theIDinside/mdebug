#pragma once
#include "common.h"
#include <string_view>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

std::string_view request_name(__ptrace_request req);

void new_target_set_options(pid_t pid);

void ptrace_panic(__ptrace_request req, pid_t pid, std::string_view additional_msg = "");

template <typename Addr = std::nullptr_t, typename Data = std::nullptr_t>
constexpr void
ptrace_or_panic(auto req, pid_t pid, Addr addr = {}, Data data = {})
{
  if (-1 == ptrace(req, pid, addr, data)) {
    ptrace_panic(req, pid);
  }
}

enum class SyscallStop : u8
{
  Entry = PTRACE_SYSCALL_INFO_ENTRY,
  Exit = PTRACE_SYSCALL_INFO_EXIT
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

private:
  __ptrace_syscall_info m_info;
};

struct SyscallArguments
{

  SyscallArguments(const user_regs_struct &regs);

#ifdef MDB_DEBUG
  void
  debug_print(bool flush, bool pretty);
#else

#endif

  union
  {
    u64 args[6];
    struct
    {
      u64 arg1;
      u64 arg2;
      u64 arg3;
      u64 arg4;
      u64 arg5;
      u64 arg6;
    };
    struct
    {
      u64 rdi;
      u64 rsi;
      u64 rdx;
      u64 r10;
      u64 r8;
      u64 r9;
    };
  } arguments;
};