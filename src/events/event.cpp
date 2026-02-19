/** LICENSE TEMPLATE */
#include "event.h"
// mdb
#include <interface/tracee_command/supervisor_state.h>
#include <task.h>
namespace mdb {
void
StopObserver::send_notifications() noexcept
{
  DBGLOG(core, "notifying {} messages", notifications.size());
  for (auto &&note : notifications) {
    note->Send();
  }
  notifications.clear();
}

Step::Step(tc::SupervisorState &tc, int tid, std::string_view msg) noexcept : tc(tc), tid(tid), msg(msg) {}

void
Step::Send() noexcept
{
  tc.EmitSteppedStop({ .pid = tc.TaskLeaderTid(), .tid = tid }, msg, true);
}

BreakpointHit::BreakpointHit(tc::SupervisorState &tc, int bp_id, int tid) noexcept : tc(tc), bp_id(bp_id), tid(tid)
{
}

void
BreakpointHit::Send() noexcept
{
  tc.EmitStoppedAtBreakpoints({ .pid = tc.TaskLeaderTid(), .tid = tid }, bp_id, true);
}

SignalStop::SignalStop(tc::SupervisorState &supervisor, int tid) noexcept : mSupervisor(supervisor), mTid(tid) {}

void
SignalStop::Send() noexcept
{
  mSupervisor.EmitSignalEvent({ .pid = mSupervisor.TaskLeaderTid(), .tid = mTid });
}
} // namespace mdb

namespace mdb::pub {
#define EACH_FN(EVT, DESC, RET, ...) decltype(EVT) EVT{};
FOR_EACH_EVENT(EACH_FN)
#undef EACH_FN
} // namespace mdb::pub