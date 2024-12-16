#include "event.h"
#include "../supervisor.h"
#include "../task.h"

void
StopObserver::send_notifications() noexcept
{
  DBGLOG(core, "notifying {} messages", notifications.size());
  for (auto &&note : notifications) {
    note->send();
  }
  notifications.clear();
}

Step::Step(TraceeController &tc, int tid, std::string_view msg) noexcept : tc(tc), tid(tid), msg(msg) {}

void
Step::send() noexcept
{
  tc.emit_stepped_stop({tc.TaskLeaderTid(), tid}, msg, true);
}

BreakpointHit::BreakpointHit(TraceeController &tc, int bp_id, int tid) noexcept : tc(tc), bp_id(bp_id), tid(tid) {}

void
BreakpointHit::send() noexcept
{
  tc.emit_stopped_at_breakpoint({.pid = tc.TaskLeaderTid(), .tid = tid}, bp_id, true);
}

SignalStop::SignalStop(TraceeController &tc, int signal, int tid) noexcept : tc(tc), signal(signal), tid(tid) {}

void
SignalStop::send() noexcept
{
  tc.emit_signal_event({.pid = tc.TaskLeaderTid(), .tid = tid}, signal);
}