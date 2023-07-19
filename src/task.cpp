#include "task.h"
#include "ptrace.h"
#include <sys/ptrace.h>

TaskInfo::TaskInfo(pid_t tid) noexcept
    : tid(tid), wait_status(), run_type(RunType::UNKNOWN), stopped(true), stepping(false), ptrace_stop(false),
      initialized(false)
{
}

void
TaskInfo::set_taskwait(TaskWaitResult wait) noexcept
{
  wait_status = wait;
}

void
TaskInfo::set_running(RunType type) noexcept
{
  if (stopped) {
    stopped = false;
    ptrace_stop = false;
    stepping = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  } else if (ptrace_stop) {
    stopped = false;
    ptrace_stop = false;
    stepping = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  }
}

void
TaskInfo::set_stop() noexcept
{
  stopped = true;
  stepping = false;
}

void
TaskInfo::initialize() noexcept
{
  initialized = true;
}

bool
TaskInfo::can_continue() noexcept
{
  return initialized && (stopped || ptrace_stop);
}

bool
TaskInfo::is_stopped() const noexcept
{
  return ptrace_stop || stopped;
}

TaskVMInfo
TaskVMInfo::from_clone_args(const clone_args &cl_args) noexcept
{
  return {.stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls};
}