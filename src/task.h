#pragma once

#include "common.h"
#include <linux/sched.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

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
  user_regs_struct registers;
  WaitStatus ws;

  TraceePointer<void> last_byte_executed() const;

  union
  {
    int exit_signal;
    int signal;
  } data;
};

void TaskWaitResultCleanUp(TaskWaitResult *_this);

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
  pid_t tid;
  TraceePointer<void> stopped_address;
  TaskWaitResult wait_status;
  RunType run_type;

  TaskInfo(pid_t tid, TraceePointer<void> stopped_at) noexcept;
  TaskInfo() = default;
  ~TaskInfo() = default;
  TaskInfo(const TaskInfo &o) = default;
  TaskInfo(TaskInfo &&o) = default;
  TaskInfo &operator=(const TaskInfo &o) = default;

  void set_taskwait(TaskWaitResult wait) noexcept;
  void set_running(RunType) noexcept;
  void request_registers() noexcept;
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
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx);

  template <typename FormatContext> auto format(TaskVMInfo const &vm_info, FormatContext &ctx);
};

template <typename ParseContext>
constexpr auto
formatter<TaskVMInfo>::parse(ParseContext &ctx)
{
  return ctx.begin();
}

template <typename FormatContext>
auto
formatter<TaskVMInfo>::format(TaskVMInfo const &vm_info, FormatContext &ctx)
{
  return fmt::format_to(ctx.out(), "{{ stack: {}, stack_size: {}, tls: {} }}", vm_info.stack_low.to_string(),
                        vm_info.stack_size, vm_info.tls.to_string());
}

}; // namespace fmt