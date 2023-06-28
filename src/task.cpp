#include "task.h"
#include "ptrace.h"
#include <sys/ptrace.h>

TaskInfo::TaskInfo(pid_t tid, TraceePointer<void> stopped_at) noexcept
    : stopped(true), signal_in_flight(false), stepping(false), tid(tid), stopped_address(stopped_at), run_type(RunType::UNKNOWN)
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
  PTRACE_OR_PANIC(run_type, tid, nullptr, nullptr);
}

void TaskInfo::request_registers() noexcept {
  PTRACE_OR_PANIC(PTRACE_GETREGS, tid, nullptr, &wait_status.registers);
}