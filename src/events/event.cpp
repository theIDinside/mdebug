/** LICENSE TEMPLATE */
#include "event.h"
#include "../supervisor.h"
#include "../task.h"
namespace mdb {
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
  tc.EmitSteppedStop({tc.TaskLeaderTid(), tid}, msg, true);
}

BreakpointHit::BreakpointHit(TraceeController &tc, int bp_id, int tid) noexcept : tc(tc), bp_id(bp_id), tid(tid) {}

void
BreakpointHit::send() noexcept
{
  tc.EmitStoppedAtBreakpoints({.pid = tc.TaskLeaderTid(), .tid = tid}, bp_id, true);
}

SignalStop::SignalStop(TraceeController &tc, int signal, int tid) noexcept : tc(tc), signal(signal), tid(tid) {}

void
SignalStop::send() noexcept
{
  tc.EmitSignalEvent({.pid = tc.TaskLeaderTid(), .tid = tid}, signal);
}
} // namespace mdb

namespace mdb::pub {
#define EACH_FN(EVT, DESC, RET, ...) decltype(EVT) EVT{};
FOR_EACH_EVENT(EACH_FN)
#undef EACH_FN
} // namespace mdb::pub