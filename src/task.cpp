#include "task.h"
#include "ptrace.h"
#include "symbolication/callstack.h"
#include <sys/ptrace.h>
#include <sys/user.h>

TaskInfo::TaskInfo(pid_t tid) noexcept
    : tid(tid), wait_status(), user_stopped(true), tracer_stopped(true), initialized(false), cache_dirty(true),
      rip_dirty(true), exited(false), registers(new user_regs_struct{}), call_stack(new sym::CallStack{tid})
{
}

u64
TaskInfo::get_register(u64 reg_num) noexcept
{
  return ::get_register(registers, reg_num);
}

void
TaskInfo::cache_registers() noexcept
{
  if (cache_dirty) {
    PTRACE_OR_PANIC(PTRACE_GETREGS, tid, nullptr, registers);
    cache_dirty = false;
    rip_dirty = false;
  }
}

void
TaskInfo::set_taskwait(TaskWaitResult wait) noexcept
{
  wait_status = wait.ws;
}

void
TaskInfo::resume(RunType type) noexcept
{

  if (user_stopped) {
    DLOG("mdb", "restarting {} from user-stop", tid);
    user_stopped = false;
    tracer_stopped = false;
    PTRACE_OR_PANIC(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, tid, nullptr, nullptr);
  } else if (tracer_stopped) {
    DLOG("mdb", "restarting {} from tracer-stop", tid);
    user_stopped = false;
    tracer_stopped = false;
    PTRACE_OR_PANIC(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, tid, nullptr, nullptr);
  }
  set_dirty();
}

void
TaskInfo::set_stop() noexcept
{
  user_stopped = true;
}

void
TaskInfo::initialize() noexcept
{
  initialized = true;
}

bool
TaskInfo::can_continue() noexcept
{
  return initialized && (user_stopped || tracer_stopped) && !exited;
}

void
TaskInfo::set_dirty() noexcept
{
  cache_dirty = true;
  rip_dirty = true;
  call_stack->dirty = true;
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
  return user_stopped;
}

TaskVMInfo
TaskVMInfo::from_clone_args(const clone_args &cl_args) noexcept
{
  return {.stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls};
}