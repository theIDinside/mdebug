#include "task.h"
#include "ptrace.h"
#include <sys/ptrace.h>

TaskInfo::TaskInfo(pid_t tid, TraceePointer<void> stopped_at) noexcept
    : stopped(true), signal_in_flight(false), stepping(false), tid(tid), stopped_address(stopped_at),
      run_type(RunType::UNKNOWN)
{
}

void
TaskInfo::set_taskwait(TaskWaitResult wait) noexcept
{
  this->stopped = true;
  wait_status = wait;
}

void
TaskInfo::set_running(RunType type) noexcept
{
  stopped = false;
  signal_in_flight = false;
  stepping = false;
  run_type = type;
  PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
}

void
TaskInfo::request_registers() noexcept
{
  PTRACE_OR_PANIC(PTRACE_GETREGS, tid, nullptr, &wait_status.registers);
}

TraceePointer<void>
TaskWaitResult::last_byte_executed() const
{
  return registers.rip - 1;
}

TaskVMInfo
TaskVMInfo::from_clone_args(const clone_args &cl_args) noexcept
{
  return {.stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls};
}