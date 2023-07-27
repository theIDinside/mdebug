#include "ptracestop_handlers.h"
#include "tracee_controller.h"

namespace ptracestop {

InstructionStep::InstructionStep(TraceeController *tc, Tid thread_id, int steps, bool single_thread) noexcept
    : Action(tc), thread_id(thread_id), steps(steps), tsi(tc->prepare_foreach_thread<TaskStepInfo>())
{
  ASSERT(steps > 0, "Instruction stepping with 0 as param not valid");
  for (auto &t : tc->threads) {
    if (t.tid == thread_id) {
      tsi.insert(tsi.begin(), {.tid = t.tid, .steps = steps, .ignore_bps = false, .rip = tc->get_caching_pc(&t)});
    } else if (!single_thread) {
      tsi.push_back({.tid = t.tid, .steps = steps, .ignore_bps = false, .rip = tc->get_caching_pc(&t)});
    }
  }
  next = tsi.begin();
}

bool
InstructionStep::do_next_action(TaskInfo *t, bool should_stop) noexcept
{
  LOG("mdb", "Should we emit step stop? {}", done);
  if (!should_stop) {
    if (done) {
      tc->emit_stepped_stop(LWP{.pid = tc->task_leader, .tid = thread_id});
    } else {
      step_one();
    }
    return done;
  } else {
    return true;
  }
}

void
InstructionStep::start_action() noexcept
{
  step_one();
}

bool
InstructionStep::check_if_done() noexcept
{
  if (next == tsi.end()) {
    done = (--steps == 0);
    next = tsi.begin();
  }
  return done;
}

void
InstructionStep::step_one() noexcept
{
  LOG("mdb", "Stepping {} one step", next->tid);
  auto bpstat = find(tc->user_brkpts.task_bp_stats, [t = next->tid](auto &bpstat) { return bpstat.tid == t; });
  bool stepped_over_bp = false;
  if (bpstat != std::end(tc->user_brkpts.task_bp_stats)) {
    auto bp = tc->user_brkpts.get_by_id(bpstat->bp_id);
    LOG("mdb", "[step_one]: Disabling breakpoint {} for tid {}", bpstat->bp_id, next->tid);
    bp->disable(next->tid);
    stepped_over_bp = true;
  }

  VERIFY(-1 != ptrace(PTRACE_SINGLESTEP, bpstat->tid, 0, 0),
         "Single step over user breakpoint boundary failed: {}", strerror(errno));
  auto rip = ptrace(PTRACE_PEEKUSER, next->tid, offsetof(user_regs_struct, rip), 0);
  next->step_taken_to(rip);
  if (stepped_over_bp) {
    bpstat->stepped_over = true;
    tc->user_brkpts.enable_breakpoint(bpstat->bp_id);
  }
  ++next;

  check_if_done();
}

LineStep::LineStep(TraceeController *tc, Tid thread_id, int lines, bool single_thread) noexcept
    : InstructionStep(tc, thread_id, lines, single_thread)
{
}

void
LineStep::start_action() noexcept
{
  tc->build_callframe_stack(tc->get_task(next->tid));
}

bool
LineStep::check_if_done() noexcept
{
}

StopHandler::StopHandler(TraceeController *tc) noexcept
    : tc(tc), action(new Action{tc}), default_action(action), should_stop(false),
      stop_all(true), event_settings{.bitset = 0x00} // all OFF by default
{
}

void
StopHandler::handle_execution_event(TaskInfo *stopped) noexcept
{
  stopped->set_dirty();
  switch (stopped->wait_status.ws) {
  case WaitStatusKind::Stopped: {
    const auto tevt = tc->process_stopped(stopped);
    switch (tevt.event) {
    case TracerWaitEvent::BreakpointHit: {
      handle_breakpoint_event(stopped, tevt.bp);
      break;
    }
    case TracerWaitEvent::None:
      handle_generic_stop(stopped);
      break;
    case TracerWaitEvent::WatchpointHit:
      TODO("TracerWaitEvent::WatchpointHit");
      break;
    }
  } break;
  case WaitStatusKind::Execed: {
    tc->process_exec(stopped);
    handle_execed(stopped);
    break;
  }
  case WaitStatusKind::Exited: {
    handle_exited(stopped);
    break;
  }
  case WaitStatusKind::Cloned: {
    tc->process_clone(stopped);
    handle_cloned(stopped);
    break;
  }
  case WaitStatusKind::Forked:
    break;
  case WaitStatusKind::VForked:
    break;
  case WaitStatusKind::VForkDone:
    break;
  case WaitStatusKind::Signalled:
    handle_signalled(stopped);
    break;
  case WaitStatusKind::SyscallEntry:
    break;
  case WaitStatusKind::SyscallExit:
    break;
  default:
    break;
  }
  tc->reaped_events();
  if (action->do_next_action(stopped, should_stop)) {
    delete action;
    action = default_action;
    should_stop = false;
  }
}

void
StopHandler::handle_breakpoint_event(TaskInfo *task, Breakpoint *bp) noexcept
{
  tc->user_brkpts.add_bpstat_for(task, bp);
  tc->stop_all();
  tc->emit_stopped_at_breakpoint({.pid = tc->task_leader, .tid = task->tid}, bp->bp_id);
  should_stop = true;
}

void
StopHandler::handle_generic_stop(TaskInfo *stopped) noexcept
{
  should_stop = false;
}

void
StopHandler::handle_signalled(TaskInfo *t) noexcept
{
  should_stop = true;
  tc->stop_all();
  tc->emit_signal_event({.pid = tc->task_leader, .tid = t->tid}, t->wait_status.data.signal);
}

void
StopHandler::handle_execed(TaskInfo *t) noexcept
{
  should_stop = event_settings.exec_stop;
}
void
StopHandler::handle_exited(TaskInfo *t) noexcept
{
  tc->reap_task(t);
  should_stop = event_settings.thread_exit_stop;
}
void
StopHandler::handle_cloned(TaskInfo *t) noexcept
{
  should_stop = event_settings.clone_stop;
}

void
StopHandler::can_resume() noexcept
{
  should_stop = false;
}

void
StopHandler::set_stop_all() noexcept
{
  event_settings.bitset = 0xff;
}

constexpr void
StopHandler::stop_on_clone() noexcept
{
  event_settings.clone_stop = true;
}
constexpr void
StopHandler::stop_on_exec() noexcept
{
  event_settings.exec_stop = true;
}
constexpr void
StopHandler::stop_on_thread_exit() noexcept
{
  event_settings.thread_exit_stop = true;
}
constexpr void
StopHandler::ignore_bps() noexcept
{
  event_settings.ignore_bps = true;
}

void
StopHandler::do_next_action(TaskInfo *t) noexcept
{
  if (!should_stop) {
    t->set_running(RunType::Continue);
  }
}

void
StopHandler::set_action(Action *action) noexcept
{
  this->action = action;
}

void
StopHandler::restore_default() noexcept
{
  ASSERT(action != default_action, "Deleting default action handler!");
  delete action;
  action = default_action;
}

void
StopHandler::start_action() noexcept
{
  action->start_action();
}

} // namespace ptracestop