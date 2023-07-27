#include "ptracestop_handlers.h"
#include "symbolication/lnp.h"
#include "tracee_controller.h"
#include <algorithm>

namespace ptracestop {

InstructionStep::InstructionStep(TraceeController *tc, Tid thread_id, int steps, bool single_thread) noexcept
    : Action(tc), thread_id(thread_id), steps(steps), done(false), tsi(tc->prepare_foreach_thread<TaskStepInfo>())
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
  if (!should_stop) {
    return step_one();
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
  return done;
}

void
InstructionStep::update_step_schedule() noexcept
{
  ++next;
  if (next == tsi.end()) {
    done = (--steps == 0);
    next = tsi.begin();
  }
}

bool
InstructionStep::step_one() noexcept
{
  if (check_if_done()) {
    tc->emit_stepped_stop(LWP{.pid = tc->task_leader, .tid = thread_id});
    return true;
  }
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
  if (stepped_over_bp) {
    bpstat->stepped_over = true;
    tc->user_brkpts.enable_breakpoint(bpstat->bp_id);
  }

  update_step_schedule();
  return false;
}

LineStep::LineStep(TraceeController *tc, Tid thread_id, int lines, bool single_thread) noexcept
    : InstructionStep(tc, thread_id, lines, single_thread)
{
}

void
LineStep::start_action() noexcept
{
  auto &callstack = tc->build_callframe_stack(tc->get_task(next->tid));
  start_frame = callstack.frames[0];
  if (auto cu_idx = tc->cu_file_from_pc(start_frame.rip); cu_idx) {
    const auto [a, b] = tc->cu_files()[*cu_idx].get_range(start_frame.rip);
    ASSERT(a != nullptr, "Expected a line table entry");
    entry = *a;
    cu = &tc->cu_files()[*cu_idx];
    step_one();
  } else {
    // we could not find any source debug information; abort installed stepper.
    done = true;
  }
}

void
LineStep::update_step_schedule() noexcept
{
  ++next;
  if (next == std::end(tsi))
    next = tsi.begin();
}

bool
LineStep::check_if_done() noexcept
{
  auto stepped_tid = next->tid;
  // we don't care what all the other threads are doing, we just step them.
  if (stepped_tid != thread_id)
    return false;

  auto &callstack = tc->build_callframe_stack(tc->get_task(stepped_tid));
  if (auto frameidx = callstack.has_frame(start_frame); frameidx) {
    auto &f = callstack.frames[*frameidx];
    const auto [a, b] = cu->get_range(f.rip);
    ASSERT(a != nullptr && b != nullptr, "Expected to be able to find lte range.")
    if (a->line != entry.line) {
      done = true;
    }
  } else {
    done = true;
  }
  return done;
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
    TODO("WaitStatusKind::Forked");
    break;
  case WaitStatusKind::VForked:
    TODO("WaitStatusKind::VForked");
    break;
  case WaitStatusKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case WaitStatusKind::Signalled:
    handle_signalled(stopped);
    break;
  case WaitStatusKind::SyscallEntry:
    TODO("WaitStatusKind::SyscallEntry");
    break;
  case WaitStatusKind::SyscallExit:
    TODO("WaitStatusKind::SyscallExit");
    break;
  default:
    break;
  }

  // If we have a stepper installed, perform it's action
  if (action->do_next_action(stopped, should_stop)) {
    delete action;
    action = default_action;
    should_stop = false;
  }
  tc->reaped_events();
}

void
StopHandler::handle_breakpoint_event(TaskInfo *task, Breakpoint *bp) noexcept
{
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
  LOG("mdb", "Starting action...");
  action->start_action();
}

} // namespace ptracestop