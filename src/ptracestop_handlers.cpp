#include "ptracestop_handlers.h"
#include "breakpoint.h"
#include "common.h"
#include "symbolication/lnp.h"
#include "task.h"
#include "tracee_controller.h"
#include "tracer.h"
#include "utils/logger.h"
#include <algorithm>
#include <chrono>
#include <sys/wait.h>

namespace ptracestop {

Action::Action(StopHandler *handler) noexcept
    : handler(handler), tc(handler->tc), should_stop(false), step_over_breakpoint(nullptr)
{
}

Action::~Action() noexcept { handler->is_stepping = false; }

bool
Action::completed(TaskInfo *t, bool should_stop) noexcept
{
  constexpr bool is_done = false;
  DLOG("mdb", "[action]: {} will resume => {}", t->tid, !should_stop && t->can_continue());
  if (!should_stop && t->can_continue()) {
    if (step_over_breakpoint) {
      t->step_over_breakpoint(tc);
      step_over_breakpoint = nullptr;
    }
    t->resume(RunType::Continue);
  }
  return is_done;
}

InstructionStep::InstructionStep(StopHandler *handler, Tid thread_id, int steps, bool single_thread) noexcept
    : Action(handler), thread_id(thread_id), steps(steps), debug_steps_taken(0), done(false),
      single_threaded_stepping(single_thread), tsi(handler->tc->prepare_foreach_thread<TaskStepInfo>())
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
InstructionStep::completed(TaskInfo *, bool should_stop) noexcept
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
  handler->is_stepping = true;
  handler->set_should_stop(false);
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

void
InstructionStep::new_task_created(TaskInfo *t) noexcept
{
  if (!single_threaded_stepping) {
    // re-set iterator
    const auto idx = std::distance(tsi.begin(), next);
    tsi.push_back({.tid = t->tid, .steps = steps, .ignore_bps = false, .rip = nullptr});
    next = tsi.begin() + idx;
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

  auto task = tc->get_task(next->tid);
  if (task->bstat) {
    DLOG("mdb", "[ptrace stop:istep]: breakpoint step-over");
    auto bp = tc->bps.get_by_id(task->bstat->bp_id);
    bp->disable(tc->task_leader);
    task->resume(RunType::Step);
    bp->enable(next->tid);
    task->bstat->stepped_over = true;
  } else {
    DLOG("mdb", "[ptrace stop:istep]: resume");
    resume_impl();
  }
  update_step_schedule();
  debug_steps_taken++;
  return false;
}

void
InstructionStep::resume_impl() noexcept
{
  auto task = tc->get_task(next->tid);
  DLOG("mdb", "[InstructionStep] stepping 1 instruction");
  task->resume(RunType::Step);
}

LineStep::LineStep(StopHandler *handler, Tid thread_id, int lines, bool single_thread) noexcept
    : InstructionStep(handler, thread_id, lines, single_thread), resume_address_set(false), resume_addr(nullptr)
{
}

LineStep::~LineStep() noexcept
{
  if (resume_addr != nullptr)
    tc->remove_breakpoint(resume_addr, BpType{.resume_address = true});
  DLOG("mdb", "Ended LineStep");
}

void
LineStep::start_action() noexcept
{
  this->handler->is_stepping = true;
  start_time = std::chrono::high_resolution_clock::now();
  auto &callstack = tc->build_callframe_stack(tc->get_task(next->tid), CallStackRequest::partial(1));
  start_frame = callstack.frames[0];
  DLOG("mdb", "frame rip: {} cu: {:p} sym: {:p}. frame info {}", start_frame.rip, (void *)start_frame.cu_file,
       (void *)start_frame.symbol, start_frame);
  if (auto cu = tc->get_cu_from_pc(start_frame.rip); cu) {
    const auto [a, b] = cu->get_range(start_frame.rip);
    ASSERT(a != nullptr, "Expected a line table entry");
    entry = *a;
    this->cu = cu;
    resume();
    handler->set_should_stop(false);
    should_stop = false;
    DLOG("mdb", "Callstack at start");
    for (const auto &f : callstack.frames) {
      DLOG("mdb", "Frame: {}", f);
    }
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
    tc->get_task(next->tid)->resume(RunType::Continue);
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
  DLOG("mdb", "frame: {}; start-frame: {}", frame, start_frame);
  if (same_symbol(frame, start_frame)) {
    const auto [a, b] = cu->get_range_of_pc(frame.rip);
    if (!a || !b)
      return done;
    handler->is_stepping = true;
    if (a->line != entry.line) {
      DLOG("mdb", "New LTE pc {} found by using {}, line {} != start LTE pc {}, line {}. (pc {}, line {})", a->pc,
           frame.rip, a->line, entry.pc, entry.line, b->pc, b->line);
      done = true;
    }
  } else {
    DLOG("mdb", "{} left origin frame {} ----> {}", next->tid, start_frame, frame);
    // we've left the origin frame; let's try figure out a place we can set a breakpoint
    // so that we can skip single stepping and instead do `PTRACE_CONT` which will be many orders of magnitude
    // faster.
    auto &callstack = tc->build_callframe_stack(task, CallStackRequest::partial(2));
    const auto resume_address = map<AddrPtr>(
        callstack.frames,
        [sf = start_frame](const auto &f) {
          if (f.symbol)
            return f.symbol->name == sf.symbol->name;
          return same_symbol(f, sf);
        },
        sym::resume_address);
    if (resume_address) {
      tc->set_tracer_bp(resume_address->as<u64>(), BpType{.resume_address = true});
      resume_address_set = true;
      resume_addr = *resume_address;
      handler->is_stepping = false;
    } else {
      DLOG("mdb", "COULD NOT DETERMINE RESUME ADDRESS? REALLY?: CALLSTACK:");
      for (const auto &frame : callstack.frames) {
        DLOG("mdb", "{}", frame);
      }
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
    const auto stopped_tid = stopped->tid;
    const auto new_task_tid = tc->process_clone(stopped);
    action->new_task_created(tc->get_task(new_task_tid));
    handle_cloned(stopped);
    stopped = tc->get_task(stopped_tid);
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
  if (action->completed(stopped, should_stop)) {
    DLOG("mdb", "Deleting action because should_stop ?= {}", should_stop);
    delete action;
    action = default_action;
    set_should_stop(false);
  }
  // NB: *ONLY* notify self when _100%_ sure there is a waitable event waiting to be read, otherwise will block
  // main thread.
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
    set_should_stop(true);
    break;
  }
  case BpEventType::None:
    break;
  case BpEventType::TracerBreakpointHit: {
    action->set_step_over(&t->bstat.value());
    if (evt.bp->bp_type.shared_object_load) {
      tc->on_so_event();
    }
  } break;
  }
}

void
StopHandler::handle_signalled(TaskInfo *t) noexcept
{
  set_should_stop(true);
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
  set_should_stop(event_settings.thread_exit_stop);
}
void
StopHandler::handle_cloned(TaskInfo *) noexcept
{
  if (!should_stop && !is_stepping)
    set_should_stop(event_settings.clone_stop);
}

void
StopHandler::can_resume() noexcept
{
  set_should_stop(false);
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

bool
StopHandler::set_should_stop(bool stop) noexcept
{
  DLOG("mdb", "Setting should stop = {} to {}", should_stop, stop);
  should_stop = stop;
  return should_stop;
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
  DLOG("mdb", "[ptrace stop]: start action...");
  action->start_action();
}

} // namespace ptracestop