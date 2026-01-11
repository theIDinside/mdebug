/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp.h>
#include <common/macros.h>
#include <common/typedefs.h>
#include <event_queue_types.h>

// std
#include <format>
#include <memory>
#include <optional>
#include <string>

// system
#include <sys/poll.h>

namespace mdb {

class TaskInfo;

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
namespace ui {
struct UICommand;
namespace dap {
class DebugAdapterManager;
}

} // namespace ui

#define EventType(Type) static constexpr TracerEventType EvtType = TracerEventType::Type // NOLINT
} // namespace mdb

template <> struct std::formatter<mdb::TracerEventType>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &context)
  {
    return context.begin();
  }

  template <typename FormatContext>
  auto
  format(const ::mdb::TracerEventType &evt, FormatContext &ctx) const
  {
    using enum ::mdb::TracerEventType;
    switch (evt) {
    case Stop:
      return std::format_to(ctx.out(), "TracerEventType::Stop");
    case LibraryEvent:
      return std::format_to(ctx.out(), "TracerEventType::LibraryEvent");
    case BreakpointHitEvent:
      return std::format_to(ctx.out(), "TracerEventType::BreakpointHitEvent");
    case SyscallEvent:
      return std::format_to(ctx.out(), "TracerEventType::SyscallEvent");
    case ThreadCreated:
      return std::format_to(ctx.out(), "TracerEventType::ThreadCreated");
    case ThreadExited:
      return std::format_to(ctx.out(), "TracerEventType::ThreadExited");
    case WatchpointEvent:
      return std::format_to(ctx.out(), "TracerEventType::WatchpointEvent");
    case ProcessExited:
      return std::format_to(ctx.out(), "TracerEventType::ProcessExited");
    case ProcessTerminated:
      return std::format_to(ctx.out(), "TracerEventType::ProcessTerminated");
    case Fork:
      return std::format_to(ctx.out(), "TracerEventType::Fork");
    case VFork:
      return std::format_to(ctx.out(), "TracerEventType::VFork");
    case VForkDone:
      return std::format_to(ctx.out(), "TracerEventType::VForkDone");
    case Exec:
      return std::format_to(ctx.out(), "TracerEventType::Exec");
    case Clone:
      return std::format_to(ctx.out(), "TracerEventType::Clone");
    case DeferToSupervisor:
      return std::format_to(ctx.out(), "TracerEventType::DeferToProceed");
    case Signal:
      return std::format_to(ctx.out(), "TracerEventType::Signal");
    case Stepped:
      return std::format_to(ctx.out(), "TracerEventType::Stepped");
    case Entry:
      return std::format_to(ctx.out(), "TracerEventType::Entry");
    }
    NEVER("Unknown Core event type");
  }
};

namespace mdb {
struct TaskEvent
{
  Tid mThreadId;
};

struct WatchpointEvent : public TaskEvent
{
  EventType(WatchpointEvent);
  enum class WatchpointType : u8
  {
    Read,
    Write,
    Access
  };

  WatchpointType mWatchpointType;
  std::uintptr_t mAddress;
};

struct SyscallEvent : public TaskEvent
{
  EventType(SyscallEvent);
  enum class Boundary : u8
  {
    Entry,
    Exit
  };

  Boundary mBoundary;
  int mSyscallNumber;
};

struct ThreadCreated : public TaskEvent
{
  EventType(ThreadCreated);
  tc::RunType mResumeAction;
};

struct ThreadExited : public TaskEvent
{
  EventType(ThreadExited);
  int mCodeOrSignal;
  bool mProcessNeedsResuming;
};

struct ForkEvent : public TaskEvent
{
  EventType(Fork);
  Pid mChildPid;
  bool mIsVFork;
};

struct Clone : public TaskEvent
{
  EventType(Clone);
  Tid mChildTid;
  std::optional<TraceePointer<void>> mStackLow;
  std::optional<u64> mStackSize;
  std::optional<TraceePointer<void>> mTLS;
};

struct Exec : public TaskEvent
{
  EventType(Exec);
  std::string mExecFile;
};

struct ProcessExited : public TaskEvent
{
  EventType(ProcessExited);
  Pid mProcessId;
  int mExitCode;
};

struct LibraryEvent : public TaskEvent
{
  EventType(LibraryEvent);
};

struct Signal : public TaskEvent
{
  EventType(Signal);
  int mTerminatingSignal;
};

struct Stepped : public TaskEvent
{
  EventType(Stepped);
  bool mStop;
  tc::RunType mResumeWhenDone{ tc::RunType::None };
  std::string_view mMessage{};
};

struct BreakpointHitEvent : public TaskEvent
{
  EventType(BreakpointHitEvent);
  enum class BreakpointType : u8
  {
    Software,
    Hardware
  };

  Immutable<BreakpointType> mBreakpointType;
  Immutable<std::optional<std::uintptr_t>> mAddress;
};

// A never-facing-user event. used to signal that a proceed action is solely responsible for determining the next
// action of a task
struct DeferToSupervisor : public TaskEvent
{
  EventType(DeferToSupervisor);
  bool mAttached;
};

struct EntryEvent : public TaskEvent
{
  EventType(Entry);
  bool mShouldStop;
};

class RegisterSpec;

// Create custom type instead of this
// Moving a `RegisterData` that is empty (default constructed) is fairly cheap; it's 24 bytes, all set to 0. But we
// can squeeze that down to 16, making it register friendly (and this would be done by using a pointer + 2 u32 for
// cap and size, instead of three pointers head, end, current, which is std::vec implementation)
using RegisterData = std::vector<std::pair<u32, std::vector<u8>>>;

using CoreEventVariant = std::variant<BreakpointHitEvent,
  Clone,
  DeferToSupervisor,
  EntryEvent,
  Exec,
  ForkEvent,
  LibraryEvent,
  ProcessExited,
  Signal,
  Stepped,
  SyscallEvent,
  ThreadCreated,
  ThreadExited,
  WatchpointEvent>;

/**
 * Core events are events generated by the the debugger core
 * It can be wait status events that has been massaged into core events, or it can be direct core events when they
 * come from a remote (via gdb remote protocol, see for instance 'stop reason' on stop replies)
 */
struct TraceEvent
{
  static int sMonotonicEventTime;
  static int NextEventTime() noexcept;

private:
  constexpr void SetGeneralEventData(const EventDataParam &param, RegisterData &&regs) noexcept;
  // The register data for this task during this event (can be empty)

public:
  RegisterData mRegisterData{};
  // The process for which this core event was generated for
  Pid mProcessId{ 0 };
  // The thread for which this core event was generated for
  Tid mTaskId{ 0 };
  // The payload std::variant, which holds the data and therefore determines what kind of event this is
  CoreEventVariant mEvent;
  // The signal generated (or the exit code returned) by the process that generated the
  TracerEventType mEventType{ TracerEventType::DeferToSupervisor };
  // For sessions where a "time" can be determined (only record & replay)
  int mEventTime;

  // Safe to pass in a reference: pointers to TaskInfo are stable for their entire existence (which last the entire
  // session. We never actually destroy TaskInfos);
  explicit TraceEvent() noexcept;
  explicit TraceEvent(int eventTime) noexcept;
  constexpr ~TraceEvent() noexcept = default;

  union
  {
    int uSignal;
    int uExitCode;
  };
  // Potential thread's register contents. When dealing with GDB Remote protocol, it can actually
  // pass some of the register contents along with it's "stop replies" (basically events that is equivalent to
  // result of the syscall waitpid(...)). If the target is native, this will always be empty.

  static void InitLibraryEvent(TraceEvent *event, const EventDataParam &param, RegisterData &&reg) noexcept;
  static void InitSoftwareBreakpointHit(TraceEvent *event,
    const EventDataParam &param,
    std::optional<std::uintptr_t> address,
    RegisterData &&reg) noexcept;
  static void InitHardwareBreakpointHit(TraceEvent *event,
    const EventDataParam &param,
    std::optional<std::uintptr_t> address,
    RegisterData &&reg) noexcept;
  static void InitSyscallEntry(
    TraceEvent *event, const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static void InitSyscallExit(
    TraceEvent *event, const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static void InitThreadCreated(
    TraceEvent *event, const EventDataParam &param, tc::RunType runType, RegisterData &&reg) noexcept;
  static void InitThreadExited(
    TraceEvent *event, const EventDataParam &param, bool processNeedsResuming, RegisterData &&reg) noexcept;
  static void InitWriteWatchpoint(
    TraceEvent *event, const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept;
  static void InitReadWatchpoint(
    TraceEvent *event, const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept;
  static void InitAccessWatchpoint(
    TraceEvent *event, const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept;
  static void InitForkEvent_(
    TraceEvent *event, const EventDataParam &param, Pid newPid, RegisterData &&reg) noexcept;
  static void InitVForkEvent_(
    TraceEvent *event, const EventDataParam &param, Pid newPid, RegisterData &&reg) noexcept;
  static void InitCloneEvent(
    TraceEvent *event, const EventDataParam &param, Tid newTid, RegisterData &&reg) noexcept;
  static void InitExecEvent(
    TraceEvent *event, const EventDataParam &param, std::string_view execFile, RegisterData &&reg) noexcept;
  static void InitProcessExitEvent(TraceEvent *event, Pid pid, Tid tid, int exitCode, RegisterData &&reg) noexcept;
  static void InitSignal(TraceEvent *event, const EventDataParam &param, RegisterData &&reg) noexcept;
  static void InitStepped(TraceEvent *event,
    const EventDataParam &param,
    bool stop,
    tc::RunType mayResumeWith,
    RegisterData &&reg) noexcept;

  static void InitDeferToSupervisor(
    TraceEvent *event, const EventDataParam &param, RegisterData &&reg, bool attached) noexcept;
  static void InitEntryEvent(
    TraceEvent *event, const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept;
};

struct InternalEvent
{
  InternalEvent() noexcept = delete;
  InternalEvent(const InternalEvent &) noexcept = default;
  InternalEvent &operator=(const InternalEvent &) noexcept = default;

  InternalEventDiscriminant mType;
  union
  {
    InvalidateSupervisor uInvalidateSupervisor;
    TerminateDebugging uTerminateDebugging;
    InitializedWaitSystem uInitializedWaitSystem;
  };

  UnionVariantConstructor(InternalEvent, InvalidateSupervisor);
  UnionVariantConstructor(InternalEvent, TerminateDebugging);
  UnionVariantConstructor(InternalEvent, InitializedWaitSystem);
};

struct ApplicationEvent
{
  NO_COPY(ApplicationEvent);

  ApplicationEventType mEventType;
  Tid mId;
  union
  {
    PtraceEvent uPtrace;
    ReplayEvent uReplayStop;
    LeakedRef<ui::UICommand> uCommand;
    InternalEvent uInternalEvent;
  };

  constexpr explicit ApplicationEvent(LeakedRef<ui::UICommand> command) noexcept
      : mEventType(ApplicationEventType::Command), mId(0), uCommand(std::move(command))
  {
  }
  constexpr explicit ApplicationEvent(PtraceEvent ptraceEvent) noexcept
      : mEventType(ApplicationEventType::Ptrace), mId(ptraceEvent.mPid), uPtrace(ptraceEvent)
  {
  }

  constexpr explicit ApplicationEvent(ReplayEvent replayEvent) noexcept
      : mEventType(ApplicationEventType::RR), mId(replayEvent.mTaskInfo.mTaskLeader), uReplayStop(replayEvent)
  {
  }

  constexpr explicit ApplicationEvent(InternalEvent internalEvent) noexcept
      : mEventType(ApplicationEventType::Internal), mId(0), uInternalEvent(internalEvent)
  {
  }

  ApplicationEvent(ApplicationEvent &&other) noexcept : mEventType(other.mEventType), mId(other.mId)
  {
    switch (other.mEventType) {
    case ApplicationEventType::Ptrace: {
      uPtrace = other.uPtrace;
    } break;
    case ApplicationEventType::RR: {
      uReplayStop = other.uReplayStop;
    } break;
    case ApplicationEventType::Command: {
      std::construct_at(&uCommand, std::move(other.uCommand));
      break;
    }
    case ApplicationEventType::Internal: {
      uInternalEvent = other.uInternalEvent;
      break;
    }
    }
  }

  constexpr ~ApplicationEvent()
  {
    if (mEventType == ApplicationEventType::Command) {
      MDB_ASSERT(uCommand.Forget() == nullptr, "Forgot to take a reference to the command data!");
    }
  }
};

/// Result from a (successful) waitpid operation.
/// This type is serialized over a pipe from either signal handler (handling SIGCHLD as a tracer-method), or from
/// an awaiter thread, that does infinite waitpid(...)
struct WaitResult
{
  pid_t mProcessId;
  int mStatus;
};

// TODO: implement a more generic version that dynamically can add sources
//  where each interface would be a mapping of fileDescriptor => func(vector<Event>& writeTo)
//  that way we can do some thing like
//  r = poll(....)
//  for ( fd in hasEventFilter ( pds ) )
//  map[fd](res)
// This also allows for generic serialization from the notification source (see how we send waitstatus over the
// wire by just serializing it in binary form)

class EventSystem
{
  static EventSystem *sEventSystem;
  int mCommandEvents[2];
  int mInternalEvents[2];

  // The three main session notifier pipes/fd's.

  // When a gdb remote server has events to notify us of, it uses this pipe
  int mGdbServerEvents[2];
  // rr sessions use this pipe
  int mReplayStopEvents[2];
  // ptrace events are polled using signalfd, checking for SIGCHLD signals
  int mSignalFd;

  int mCurrentPolledFdsCount;
  pollfd mPollDescriptors[5];

  std::mutex mCommandsGuard{};
  std::mutex mTraceEventGuard{};
  std::mutex mInternalEventGuard{};
  ReplayEvent mLastReplayEvent;
  std::vector<TraceEvent *> mTraceEvents;
  std::vector<LeakedRef<ui::UICommand>> mCommands;
  std::vector<InternalEvent> mInternal;
  int mPollFailures = 0;

  EventSystem(int commands[2], int gdbServer[2], int replay[2], int internal[2]) noexcept;
  int PollDescriptorsCount() const noexcept;

public:
  static EventSystem *Initialize() noexcept;
  void InitWaitStatusManager() noexcept;
  void PushCommand(ui::dap::DebugAdapterManager *dap_client, RefPtr<ui::UICommand> cmd) noexcept;
  void PushReplayStopEvent(ReplayEvent event) noexcept;
  void PushInternalEvent(InternalEvent event) noexcept;
  bool PollBlocking(std::vector<ApplicationEvent> &write) noexcept;

  static EventSystem &Get() noexcept;
};
} // namespace mdb
// NOLINTEND(cppcoreguidelines-owning-memory)