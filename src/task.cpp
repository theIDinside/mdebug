#include "task.h"
#include "ptrace.h"
#include <sys/ptrace.h>

TaskInfo::TaskInfo(pid_t tid) noexcept
    : stopped(true), signal_in_flight(false), stepping(false), ptrace_stop(false), initialized(false), tid(tid),
      wait_status(), run_type(RunType::UNKNOWN)
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
    signal_in_flight = false;
    stepping = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  } else if (ptrace_stop) {
    stopped = false;
    ptrace_stop = false;
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
  return initialized && (stopped || ptrace_stop);
}

void
TaskInfo::set_pc(TPtr<void> pc) noexcept
{
  const auto rip_offset = offsetof(user_regs_struct, rip);
  VERIFY(ptrace(PTRACE_POKEUSER, tid, rip_offset, pc.get()) != -1, "Failed to set RIP register");
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