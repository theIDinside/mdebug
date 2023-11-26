#include "ptracestop_handlers.h"
#include "breakpoint.h"
#include "common.h"
#include "events/event.h"
#include "ptrace.h"
#include "supervisor.h"
#include "symbolication/lnp.h"
#include "task.h"
#include "tracer.h"
#include "utils/logger.h"
#include "utils/macros.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <chrono>
#include <sys/wait.h>

namespace ptracestop {

Action::Action(StopHandler *handler) noexcept : handler(handler), tc(handler->tc), should_stop(false) {}

Action::~Action() noexcept {}

bool
Action::completed(TaskInfo *t, bool should_resume) noexcept
{
  constexpr bool is_done = false;
  DLOG("mdb", "[action]: {} will resume (should_resume={}) => {}", t->tid, should_resume,
       should_resume && t->can_continue());
  if (should_resume && t->can_continue()) {
    tc->resume_task(t, RunType::Continue);
  }
  return is_done;
}

InstructionStep::InstructionStep(StopHandler *handler, Tid thread_id, int steps, bool single_thread) noexcept
    : Action(handler), thread_id(thread_id), steps(steps), debug_steps_taken(0), done(false),
      single_threaded_stepping(single_thread), tsi(handler->tc->prepare_foreach_thread<TaskStepInfo>())
{
  ASSERT(steps > 0, "Instruction stepping with 0 as param not valid");
  if (single_thread) {
    const auto t = tc->get_task(thread_id);
    tsi.push_back({.tid = thread_id, .steps = steps, .ignore_bps = false, .rip = tc->get_caching_pc(t)});
  } else {
    for (auto &t : tc->threads) {
      if (t.tid == thread_id) {
        tsi.insert(tsi.begin(),
                   {.tid = t.tid, .steps = steps, .ignore_bps = false, .rip = tc->get_caching_pc(&t)});
      } else {
        tsi.push_back({.tid = t.tid, .steps = steps, .ignore_bps = false, .rip = tc->get_caching_pc(&t)});
      }
    }
  }
  next = tsi.begin();
}

bool
InstructionStep::completed(TaskInfo *, bool should_resume) noexcept
{
  if (should_resume) {
    return resume();
  } else {
    return true;
  }
}

void
InstructionStep::start_action() noexcept
{
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

  resume_impl();
  update_step_schedule();
  debug_steps_taken++;
  return false;
}

void
InstructionStep::resume_impl() noexcept
{
  auto task = tc->get_task(next->tid);
  DLOG("mdb", "[InstructionStep] stepping 1 instruction for {}", task->tid);
  tc->resume_task(task, RunType::Step);
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
    const auto task = tc->get_task(next->tid);
    DLOG("mdb", "LineStep continuing sub frame for {}", task->tid);
    tc->resume_task(task, RunType::Continue);
  } else {
    DLOG("mdb", "[line step]: no resume address set, keep istepping");
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
    } else {
      DLOG("mdb", "COULD NOT DETERMINE RESUME ADDRESS? Orignal frame: {} REALLY?: CALLSTACK:", start_frame);
      for (const auto &frame : callstack.frames) {
        DLOG("mdb", "{}", frame);
      }
    }
  }
  return done;
}

StopHandler::StopHandler(TraceeController *tc) noexcept
    : tc(tc), action(new Action{this}), default_action(action), stop_all(true),
      event_settings{.bitset = 0x00} // all OFF by default
{
}

void
StopHandler::handle_wait_event(TaskInfo *info) noexcept
{
  const auto should_resume = process_waitstatus_for(info);
  if (tc->waiting_for_all_stopped) {
    if (tc->all_stopped())
      tc->notify_all_stopped();
  } else {
    action->completed(info, should_resume);
  }
  tc->reaped_events();
}

static bool
process_stopped(TraceeController *tc, TaskInfo *t)
{
  bool should_resume = true;
  auto stepped_over_bp_id = 0;
  if (t->bstat) {
    stepped_over_bp_id = t->bstat->bp_id;
    if (t->bstat->re_enable_bp) {
      tc->bps.get_by_id(t->bstat->bp_id)->enable(t->tid);
    }
    should_resume = t->bstat->should_resume;
    t->bstat = std::nullopt;
  }
  const auto pc = tc->get_caching_pc(t);
  const auto prev_pc_byte = offset(pc, -1);
  auto bp = tc->bps.get(prev_pc_byte);
  if (bp != nullptr && bp->id != stepped_over_bp_id) {
    DLOG("mdb", "{} Hit breakpoint {} at {}: {}", t->tid, bp->id, prev_pc_byte, bp->type());
    tc->set_pc(t, prev_pc_byte);
    t->add_bpstat(bp);
    bp->on_hit(tc, t);
    should_resume = bp->should_resume();
  }

  DLOG("mdb", "Processed STOPPED for {}. should_resume={}, user_stopped={}", t->tid, should_resume,
       bool{t->user_stopped});
  const auto result = should_resume && !(t->user_stopped);
  return result;
}

bool
StopHandler::process_waitstatus_for(TaskInfo *t) noexcept
{
  t->set_dirty();
  t->stop_collected = true;
  const auto ws = t->pending_wait_status();
  switch (ws.ws) {
  case WaitStatusKind::Stopped: {
    return process_stopped(tc, t);
  } break;
  case WaitStatusKind::Execed:
    tc->process_exec(t);
    return !event_settings.exec_stop;
  case WaitStatusKind::Exited:
    tc->reap_task(t);
    return !event_settings.thread_exit_stop;
  case WaitStatusKind::Forked:
    TODO("WaitStatusKind::Forked");
    break;
  case WaitStatusKind::VForked:
    TODO("WaitStatusKind::VForked");
    break;
  case WaitStatusKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case WaitStatusKind::Cloned: {
    const auto new_task_tid = tc->process_clone(t);
    action->new_task_created(tc->get_task(new_task_tid));
    return !event_settings.clone_stop;
  } break;
  case WaitStatusKind::Signalled:
    tc->stop_all();
    tc->stopped_observer.add_notification<SignalStop>(tc, t->wait_status.signal, int{t->tid});
    return false;
  case WaitStatusKind::SyscallEntry:
    TODO("WaitStatusKind::SyscallEntry");
    break;
  case WaitStatusKind::SyscallExit:
    TODO("WaitStatusKind::SyscallExit");
    break;
  case WaitStatusKind::NotKnown:
    TODO("WaitStatusKind::NotKnown");
    break;
  }
  ASSERT(false, "Unknown wait status!");
  MIDAS_UNREACHABLE
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