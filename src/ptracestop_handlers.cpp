#include "ptracestop_handlers.h"
#include "breakpoint.h"
#include "common.h"
#include "symbolication/lnp.h"
#include "tracee_controller.h"
#include "tracer.h"
#include "utils/logger.h"
#include <algorithm>
#include <chrono>

namespace ptracestop {

Action::Action(StopHandler *handler) noexcept : handler(handler), tc(handler->tc), should_stop(false) {}

Action::~Action() noexcept { handler->is_stepping = false; }

bool
Action::do_next_action(TaskInfo *t, bool should_stop) noexcept
{
  constexpr bool is_done = false;
  if (!should_stop) {
    t->set_running(RunType::Continue);
  }
  return is_done;
}

InstructionStep::InstructionStep(StopHandler *handler, Tid thread_id, int steps, bool single_thread) noexcept
    : Action(handler), thread_id(thread_id), steps(steps), debug_steps_taken(0), done(false),
      tsi(handler->tc->prepare_foreach_thread<TaskStepInfo>())
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
InstructionStep::do_next_action(TaskInfo *, bool should_stop) noexcept
{
  if (!should_stop) {
    return resume();
  } else {
    return true;
  }
}

void
InstructionStep::start_action() noexcept
{
  this->handler->is_stepping = true;
  start_time = std::chrono::high_resolution_clock::now();
  resume();
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
InstructionStep::resume() noexcept
{
  if (check_if_done()) {
    const auto end = std::chrono::high_resolution_clock::now();
    const auto time = std::chrono::duration_cast<std::chrono::microseconds>(end - start_time);
    logging::get_logging()->log(
        "mdb",
        fmt::format("Stepping ({} steps) took {}us. Average time per step: {}", debug_steps_taken, time.count(),
                    static_cast<float>(time.count()) / static_cast<float>(debug_steps_taken)));
    tc->emit_stepped_stop(LWP{.pid = tc->task_leader, .tid = thread_id});
    return true;
  }
  if (!tc->bps.bpstats.empty()) {
    auto bpstat = find(tc->bps.bpstats, [t = next->tid](auto &bpstat) { return bpstat.tid == t; });
    bool stepped_over_bp = false;
    if (bpstat != std::end(tc->bps.bpstats)) {
      auto bp = tc->bps.get_by_id(bpstat->bp_id);
      bp->disable(next->tid);
      stepped_over_bp = true;
    }
    VERIFY(-1 != ptrace(PTRACE_SINGLESTEP, next->tid, 0, 0),
           "Single step over user breakpoint boundary failed: {}", strerror(errno));
    if (stepped_over_bp) {
      bpstat->stepped_over = true;
      tc->bps.enable_breakpoint(bpstat->bp_id);
    }
  } else {
    resume_impl();
  }
  update_step_schedule();
  debug_steps_taken++;
  return false;
}

void
InstructionStep::resume_impl() noexcept
{
  DLOG("mdb", "[InstructionStep] stepping 1 instruction");
  VERIFY(-1 != ptrace(PTRACE_SINGLESTEP, next->tid, 0, 0), "Failed to single step: {}", strerror(errno));
}

LineStep::LineStep(StopHandler *handler, Tid thread_id, int lines, bool single_thread) noexcept
    : InstructionStep(handler, thread_id, lines, single_thread), resume_address_set(false), resume_addr(nullptr)
{
}

LineStep::~LineStep() noexcept { tc->remove_breakpoint(resume_addr, BpType{.resume_address = true}); }

void
LineStep::start_action() noexcept
{
  this->handler->is_stepping = true;
  start_time = std::chrono::high_resolution_clock::now();
  auto &callstack = tc->build_callframe_stack(tc->get_task(next->tid));
  start_frame = callstack.frames[0];
  if (auto cu = tc->get_cu_from_pc(start_frame.rip); cu) {
    const auto [a, b] = cu->get_range(start_frame.rip);
    ASSERT(a != nullptr, "Expected a line table entry");
    entry = *a;
    this->cu = cu;
    resume();
  } else {
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

void
LineStep::resume_impl() noexcept
{
  if (resume_address_set) {
    DLOG("mdb", "LineStep continuing sub frame");
    VERIFY(-1 != ptrace(PTRACE_CONT, next->tid, 0, 0), "Failed to single step: {}", strerror(errno));
    resume_address_set = false;
  } else {
    InstructionStep::resume_impl();
  }
}

bool
LineStep::check_if_done() noexcept
{
  debug_steps_taken++;
  // we don't care what all the other threads are doing, we just step them.
  if (next->tid != thread_id)
    return false;
  auto task = tc->get_task(next->tid);
  const auto frame = tc->current_frame(task);
  // if we're in the same frame, we single step
  if (same_symbol(frame, start_frame)) {
    const auto [a, b] = cu->get_range(frame.rip);
    handler->is_stepping = true;
    if (a->line != entry.line) {
      DLOG("mdb", "New LTE pc {}, line {} != start LTE pc {}, line {}.", a->pc, a->line, entry.pc, entry.line);
      done = true;
    }
  } else {
    // we've left the origin frame; let's try figure out a place we can set a breakpoint
    // so that we can skip single stepping and instead do `PTRACE_CONT` which will be many orders of magnitude
    // faster.
    auto &callstack = tc->build_callframe_stack(task);
    const auto resume_address = map<AddrPtr>(
        callstack.frames, [sf = start_frame](const auto &f) { return same_symbol(f, sf); }, sym::resume_address);
    if (resume_address) {
      tc->set_tracer_bp(resume_address->as<u64>(), BpType{.resume_address = true});
      resume_address_set = true;
      resume_addr = *resume_address;
      handler->is_stepping = false;
    }
  }
  return done;
}

StopHandler::StopHandler(TraceeController *tc) noexcept
    : tc(tc), action(new Action{this}), default_action(action), should_stop(false),
      stop_all(true), event_settings{.bitset = 0x00}, is_stepping(false) // all OFF by default
{
}

void
StopHandler::handle_execution_event(TaskInfo *stopped) noexcept
{
  stopped->set_dirty();
  switch (stopped->wait_status.ws) {
  case WaitStatusKind::Stopped: {
    const auto tevt = tc->process_stopped(stopped);
    handle_bp_event(stopped, tevt);
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
  if (is_stepping)
    tc->notify_self();
  else
    tc->reaped_events();
}

void
StopHandler::handle_bp_event(TaskInfo *t, BpEvent evt) noexcept
{
  switch (evt.event) {
  // even if underlying bp is both user and tracer bp; it always handles it prioritized as user.
  case BpEventType::Both:
  case BpEventType::UserBreakpointHit: {
    tc->stop_all();
    tc->emit_stopped_at_breakpoint({.pid = tc->task_leader, .tid = t->tid}, evt.bp->id);
    should_stop = true;
    break;
  }
  case BpEventType::None:
    should_stop = false;
    break;
  case BpEventType::TracerBreakpointHit:
    evt.bp->disable(t->tid);
    break;
  }
}

void
StopHandler::handle_generic_stop(TaskInfo *) noexcept
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
StopHandler::handle_execed(TaskInfo *) noexcept
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
StopHandler::handle_cloned(TaskInfo *) noexcept
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
  DLOG("mdb", "Starting action...");
  action->start_action();
}

} // namespace ptracestop