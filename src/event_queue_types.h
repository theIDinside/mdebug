/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <mdbsys/stop_status.h>

// std
#include <optional>

namespace rr {
class ReplayTask;
}

namespace mdb {

namespace tc {
class SupervisorState;
}

enum class ApplicationEventType : u8
{
  Ptrace,
  RR,
  Command,
  Internal,
};

struct PtraceEvent
{
  int mPid;
  int mStatus;
  int mCpuCore;
};

struct TraceFrameTaskContext
{
  uint64_t mRIP;
  int64_t mFrameTime;
  int64_t mTaskTickCount;
  int mSignal;
  pid_t mRecTid;
  pid_t mTaskLeader;
  pid_t mNewTaskIfAny : 31;
  bool mIsValid : 1;

  constexpr bool
  HasData() const noexcept
  {
    return mIsValid;
  }

  static TraceFrameTaskContext From(int signal, const rr::ReplayTask &task, pid_t newChild = 0) noexcept;

  constexpr static TraceFrameTaskContext
  None() noexcept
  {
    return TraceFrameTaskContext{ 0, 0, 0, 0, 0, 0, 0, false };
  }
};

struct ReplayEvent
{
  TraceFrameTaskContext mTaskInfo;
  StopKind mStopKind;
  bool mSteppingCompleted{ false };
  bool mHitBreakpoint{ false };
  bool mHitWatchpoint{ false };
};

enum class TracerEventType : u8
{
  BreakpointHitEvent,
  Clone,
  DeferToSupervisor,
  Entry,
  Exec,
  Fork,
  LibraryEvent,
  ProcessExited,
  ProcessTerminated,
  Signal,
  Stepped,
  Stop,
  SyscallEvent,
  ThreadCreated,
  ThreadExited,
  VFork,
  VForkDone,
  WatchpointEvent,
};

struct EventDataParam
{
  SessionId target;
  std::optional<int> tid;
  std::optional<int> sig_or_code;
  std::optional<int> event_time;
};

enum class InternalEventDiscriminant : u8
{
  InvalidateSupervisor,
  TerminateDebugging,
  InitializedWaitSystem,
};

// Event sent when a supervisor for a process "dies". Was called "DestroySupervisor" before
// but seeing as the plan is to integrate with RR at some point, it's better to just call it "invalidate" instead
// so that it can be potentially lifted back into life, if the user reverse-continues across the boundary of it's
// normal death.
struct InvalidateSupervisor
{
  tc::SupervisorState *mSupervisor;
};

struct TerminateDebugging
{
};

struct InitializedWaitSystem
{
};
} // namespace mdb