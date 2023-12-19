#include "ptracestop_handlers.h"
#include <breakpoint.h>
#include <common.h>
#include <events/event.h>
#include <ptrace.h>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/objfile.h>
#include <task.h>
#include <tracer.h>

namespace ptracestop {

ThreadProceedAction::ThreadProceedAction(StopHandler *handler, TaskInfo *task) noexcept
    : tc(handler->tc), task(task), cancelled(false)
{
}

void
ThreadProceedAction::cancel() noexcept
{
  cancelled = true;
}

InstructionStep::InstructionStep(StopHandler *handler, TaskInfo *thread, int steps) noexcept
    : ThreadProceedAction(handler, thread), steps_requested(steps), steps_taken(0)
{
}

bool
InstructionStep::has_completed() const noexcept
{
  return steps_taken == steps_requested;
}

void
InstructionStep::proceed() noexcept
{
  DLOG("mdb", "[InstructionStep] stepping 1 instruction for {}", task->tid);
  tc->resume_task(task, RunType::Step);
}

void
InstructionStep::update_stepped() noexcept
{
  ++steps_taken;
}

InstructionStep::~InstructionStep()
{
  if (!cancelled) {
    DLOG("mdb", "[inst step]: instruction step for {} ended", task->tid);
    tc->emit_stepped_stop(LWP{.pid = tc->task_leader, .tid = task->tid}, false);
  }
}

LineStep::LineStep(StopHandler *handler, TaskInfo *task, int lines) noexcept
    : ThreadProceedAction(handler, task), lines_requested(lines), lines_stepped(0), is_done(false),
      resume_address(), resumed_to_resume_addr(false), start_frame(), entry()
{
  auto tc = handler->tc;
  auto &callstack = tc->build_callframe_stack(task, CallStackRequest::partial(1));
  start_frame = callstack.frames[0];
  ObjectFile *obj = tc->find_obj_by_pc(start_frame.rip);
  auto src_infos = obj->get_source_infos(start_frame.rip);
  bool found = false;
  // TODO(simon): Is it possible to design it such that a search here, determines the _exact_ src_info up front?
  //   so that we don't have to make sure that the found LT and it's LTE's land within the frame's low_pc / high_pc
  for (auto *src : src_infos) {
    auto ltopt = src->get_linetable();
    if (ltopt) {
      auto lt = *ltopt;
      const auto iter = lt.find_by_pc(start_frame.rip);
      if (iter != std::end(lt)) {
        const sym::dw::LineTableEntry lte = iter.get();
        if (start_frame.inside(lte.pc.as_void()) == sym::InsideRange::Yes) {
          if (lte.pc == start_frame.rip) {
            found = true;
            entry = lte;
            break;
          } else {
            found = true;
            entry = (iter - 1).get();
            break;
          }
        }
      }
    }
  }
  VERIFY(found, "Couldn't find Line Table Entry Information needed to navigate source code lines");
}

LineStep::~LineStep() noexcept
{
  if (resume_address)
    tc->remove_breakpoint(*resume_address, BpType{.resume_address = true});
  if (!cancelled) {
    DLOG("mdb", "[line step]: line step for {} ended", task->tid);
    tc->emit_stepped_stop(LWP{.pid = tc->task_leader, .tid = task->tid}, false);
  }
}

bool
LineStep::has_completed() const noexcept
{
  return is_done;
}

void
LineStep::proceed() noexcept
{
  if (resume_address && !resumed_to_resume_addr) {
    DLOG("mdb", "[line step]: continuing sub frame for {}", task->tid);
    tc->resume_task(task, RunType::Continue);
    resumed_to_resume_addr = true;
  } else {
    DLOG("mdb", "[line step]: no resume address set, keep istepping");
    tc->resume_task(task, RunType::Step);
  }
}

void
LineStep::update_stepped() noexcept
{
  const auto frame = tc->current_frame(task);
  // if we're in the same frame, we single step
  if (same_symbol(frame, start_frame)) {
    auto lt = frame.symbol->decl_file->get_linetable();
    if (!lt) {
      is_done = true;
      return;
    }

    auto lte = lt->find_by_pc(frame.rip);
    if (lte == lt->end()) {
      is_done = true;
    }
    if (frame.rip < lte.get().pc && frame.rip > (lte - 1).get().pc) {
      return;
    }
    if ((*lte).line != entry.line) {
      is_done = true;
    }
  } else {
    auto &callstack = tc->build_callframe_stack(task, CallStackRequest::full());
    const auto ret_addr = map<AddrPtr>(
        callstack.frames,
        [sf = start_frame](const auto &f) {
          if (f.symbol)
            return f.symbol->name == sf.symbol->name;
          return same_symbol(f, sf);
        },
        sym::resume_address);
    if (ret_addr) {
      tc->set_tracer_bp(ret_addr->as<u64>(), BpType{.resume_address = true});
      resume_address = ret_addr;
    } else {
      DLOG("mdb", "COULD NOT DETERMINE RESUME ADDRESS? Orignal frame: {} REALLY?: CALLSTACK:", start_frame);
      for (const auto &frame : callstack.frames) {
        DLOG("mdb", "{}", frame);
      }
    }
  }
}

StopHandler::StopHandler(TraceeController *tc) noexcept
    : tc(tc), stop_all(true), event_settings{.bitset = 0x00}, // all OFF by default
      proceed_actions()
{
}

bool
StopHandler::has_action_installed(TaskInfo *t) noexcept
{
  return proceed_actions[t->tid] != nullptr;
}

void
StopHandler::remove_action(TaskInfo *t) noexcept
{
  ASSERT(proceed_actions.contains(t->tid), "No proceed action installed for {}", t->tid);
  ThreadProceedAction *ptr = proceed_actions[t->tid];
  delete ptr;
  proceed_actions[t->tid] = nullptr;
}

ThreadProceedAction *
StopHandler::get_proceed_action(TaskInfo *t) noexcept
{
  return proceed_actions[t->tid];
}

void
StopHandler::handle_proceed(TaskInfo *info, bool should_resume) noexcept
{
  auto proceed_action = get_proceed_action(info);
  if (proceed_action) {
    proceed_action->update_stepped();
    if (proceed_action->has_completed())
      remove_action(info);
    else
      proceed_action->proceed();
  } else {
    DLOG("mdb", "[action]: {} will resume (should_resume={}) => {}", info->tid, should_resume,
         should_resume && info->can_continue());
    if (should_resume && info->can_continue()) {
      tc->resume_task(info, RunType::Continue);
    }
  }
}

void
StopHandler::handle_wait_event(TaskInfo *info) noexcept
{
  const auto should_resume = process_waitstatus_for(info);
  if (tc->waiting_for_all_stopped) {
    if (tc->all_stopped())
      tc->notify_all_stopped();
  } else {
    handle_proceed(info, should_resume);
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

  DLOG("mdb", "[wait status]: Processed STOPPED for {}. should_resume={}, user_stopped={}", t->tid, should_resume,
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
    tc->process_clone(t);
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
StopHandler::set_action(Tid tid, ThreadProceedAction *action) noexcept
{
  proceed_actions[tid] = action;
  action->proceed();
}

} // namespace ptracestop