#include "task.h"
#include "ptrace.h"
#include "symbolication/callstack.h"
#include <sys/ptrace.h>
#include <sys/user.h>

TaskInfo::TaskInfo(pid_t tid) noexcept
    : tid(tid), wait_status(), run_type(RunType::UNKNOWN), stopped(true), ptrace_stop(false), initialized(false),
      cache_dirty(true), rip_dirty(true), registers(new user_regs_struct{}), call_stack(new sym::CallStack{tid})
{
}

void
TaskInfo::set_taskwait(TaskWaitResult wait) noexcept
{
  wait_status = wait.ws;
}

void
TaskInfo::set_running(RunType type) noexcept
{
  DLOG("mdb", "restarting {}", tid);
  if (stopped) {
    stopped = false;
    ptrace_stop = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  } else if (ptrace_stop) {
    stopped = false;
    ptrace_stop = false;
    run_type = type;
    PTRACE_OR_PANIC(PTRACE_CONT, tid, nullptr, nullptr);
  }
  set_dirty();
}

void
TaskInfo::set_stop() noexcept
{
  stopped = true;
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
TaskInfo::set_dirty() noexcept
{
  cache_dirty = true;
  rip_dirty = true;
  callstack_dirty = true;
}

void
TaskStepInfo::step_taken_to(AddrPtr rip) noexcept
{
  this->rip = rip;
  --steps;
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