#include "task.h"
#include "ptrace.h"
#include "symbolication/callstack.h"
#include "tracee_controller.h"
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
TaskInfo::consume_wait() noexcept
{
  int stat;
  waitpid(tid, &stat, 0);
  this->tracer_stopped = true;
  this->user_stopped = true;
}

void
TaskInfo::resume(RunType type) noexcept
{
  if (user_stopped) {
    DLOG("mdb", "restarting {} ({}) from user-stop", tid,
         type == RunType::Continue ? "PTRACE_CONT" : "PTRACE_SINGLESTEP");
    user_stopped = false;
    tracer_stopped = false;
    PTRACE_OR_PANIC(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, tid, nullptr, nullptr);
  } else if (tracer_stopped) {
    DLOG("mdb", "restarting {} ({}) from tracer-stop", tid,
         type == RunType::Continue ? "PTRACE_CONT" : "PTRACE_SINGLESTEP");
    user_stopped = false;
    tracer_stopped = false;
    PTRACE_OR_PANIC(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, tid, nullptr, nullptr);
  }
  set_dirty();
}

void
TaskInfo::step_over_breakpoint(TraceeController *tc, BpStat *bpstat) noexcept
{
  ASSERT(bpstat != nullptr, "Requires a valid bpstat");
  auto bp = tc->bps.get_by_id(bpstat->bp_id);
  auto it = find(tc->bps.bpstats, [t = tid](auto &bp_stat) { return bp_stat.tid == t; });
  DLOG("mdb", "Stepping over bp {} at {}", bpstat->bp_id, bp->address);
  bp->disable(tc->task_leader);
  resume(RunType::Step);
  consume_wait();
  bpstat->stepped_over = true;
  bp->enable(tc->task_leader);
  tc->bps.bpstats.erase(it);
  cache_registers();
  DLOG("mdb", "After step: {}", AddrPtr{registers->rip});
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