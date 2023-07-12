#include "task.h"
#include "ptrace.h"
#include <sys/ptrace.h>

TaskInfo::TaskInfo(pid_t tid) noexcept
    : stopped(true), signal_in_flight(false), stepping(false), stopped_by_tracer(false), initialized(false),
      tid(tid), wait_status(), run_type(RunType::UNKNOWN)
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
    signal_in_flight = false;
    stepping = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  } else if (stopped_by_tracer) {
    stopped = false;
    stopped_by_tracer = false;
    signal_in_flight = false;
    stepping = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  }
}

void
TaskInfo::set_stop() noexcept
{
  stopped = true;
  signal_in_flight = false;
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
  return initialized && (stopped || stopped_by_tracer);
}

bool
TaskInfo::is_stopped() noexcept
{
  return stopped_by_tracer || stopped;
}

TaskVMInfo
TaskVMInfo::from_clone_args(const clone_args &cl_args) noexcept
{
  return {.stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls};
}