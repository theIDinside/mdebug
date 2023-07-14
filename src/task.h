#pragma once

#include "common.h"
#include <linux/sched.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

using namespace std::string_view_literals;
enum class WaitStatus
{
#define ITEM(IT, Value) IT = Value,
#include "./defs/waitstatus.def"
#undef ITEM
};

constexpr std::string_view
to_str(WaitStatus ws)
{
  switch (ws) {
#define ITEM(IT, Value)                                                                                           \
  case WaitStatus::IT:                                                                                            \
    return #IT;
#include "./defs/waitstatus.def"
#undef ITEM
  }
}

struct TaskWaitResult
{
  pid_t waited_pid;
  WaitStatus ws;

  union
  {
    int exit_signal;
    int signal;
  } data;
};

enum class RunType : u8
{
  Step = PTRACE_SINGLESTEP,
  Continue = PTRACE_CONT,
  SyscallContinue = PTRACE_SYSCALL,
  UNKNOWN,
};

struct TaskInfo
{
  bool stopped : 1;
  bool signal_in_flight : 1;
  bool stepping : 1;
  bool stopped_by_tracer : 1;
  bool initialized : 1;
  pid_t tid;
  std::optional<TaskWaitResult> wait_status;
  RunType run_type;

  TaskInfo() = delete;
  TaskInfo(pid_t tid) noexcept;
  TaskInfo(const TaskInfo &o) noexcept = default;
  TaskInfo(TaskInfo &&o) noexcept = default;
  TaskInfo &operator=(TaskInfo &t) noexcept = default;
  TaskInfo &operator=(const TaskInfo &o) = default;

  void set_taskwait(TaskWaitResult wait) noexcept;
  void set_running(RunType) noexcept;
  void set_stop() noexcept;
  void initialize() noexcept;
  bool can_continue() noexcept;

  /*
   * Checks if this task is stopped, either `stopped_by_tracer` or `stopped` by some execution event, like a signal
   * being delivered, etc.
   */
  bool is_stopped() const noexcept;
};

struct TaskVMInfo
{
  static TaskVMInfo from_clone_args(const clone_args &cl_args) noexcept;

  TraceePointer<void> stack_low;
  u64 stack_size;
  TraceePointer<void> tls;
};

namespace fmt {
template <> struct formatter<TaskVMInfo>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(TaskVMInfo const &vm_info, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{{ stack: {}, stack_size: {}, tls: {} }}", vm_info.stack_low.to_string(),
                          vm_info.stack_size, vm_info.tls.to_string());
  }
};

template <> struct formatter<TaskInfo>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(TaskInfo const &task, FormatContext &ctx)
  {

    std::string_view wait_status = "None";
    if (task.wait_status) {
      wait_status = to_str(task.wait_status->ws);
    }

    return fmt::format_to(ctx.out(), "[Task {}] {{ stopped: {}, tracer_stopped: {}, wait_status: {} }}", task.tid,
                          task.stopped, task.stopped_by_tracer, wait_status);
  }
};

template <> struct formatter<user_regs_struct>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(user_regs_struct const &ur, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(),
                          "{{ r15: 0x{:x} r14: 0x{:x} r13: 0x{:x} r12: 0x{:x} rbp: 0x{:x} rbx: 0x{:x} r11: 0x{:x} "
                          "r10: 0x{:x} r9: 0x{:x} r8: 0x{:x} rax: 0x{:x} rcx: 0x{:x} rdx: 0x{:x} rsi: 0x{:x} rdi: "
                          "0x{:x} orig_rax: 0x{:x} rip: 0x{:x} cs: {} eflags: {} rsp: 0x{:x} ss: {} fs_base: "
                          "0x{:x} gs_base: 0x{:x} ds: 0x{:x} es: 0x{:x} fs: 0x{:x} gs: 0x{:x} }}",
                          ur.r15, ur.r14, ur.r13, ur.r12, ur.rbp, ur.rbx, ur.r11, ur.r10, ur.r9, ur.r8, ur.rax,
                          ur.rcx, ur.rdx, ur.rsi, ur.rdi, ur.orig_rax, ur.rip, ur.cs, ur.eflags, ur.rsp, ur.ss,
                          ur.fs_base, ur.gs_base, ur.ds, ur.es, ur.fs, ur.gs);
  }
};
}; // namespace fmt