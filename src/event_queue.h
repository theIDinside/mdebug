/** LICENSE TEMPLATE */
#pragma once

#include "event_queue_event_param.h"
#include "task.h"
#include <mdbsys/ptrace.h>
#include <string>
#include <sys/poll.h>
#include <variant>
namespace mdb {
namespace fmt = ::fmt;
class TraceeController;

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
namespace ui {
struct UICommand;
namespace dap {
class DebugAdapterClient;
}

} // namespace ui

enum class EventType
{
  WaitStatus,
  Command,
  TraceeEvent,
  Initialization,
  Internal,
};

struct WaitEvent
{
  TaskWaitResult mWaitResult;
  int mCpuCore;
};

enum class TracerEventType : u8
{
  Stop,
  LibraryEvent,
  BreakpointHitEvent,
  SyscallEvent,
  ThreadCreated,
  ThreadExited,
  WatchpointEvent,
  ProcessExited,
  ProcessTerminated,
  Fork,
  VFork,
  VForkDone,
  Exec,
  Clone,
  DeferToSupervisor,
  Signal,
  Stepped,
  Entry
};

#define EventType(Type) static constexpr TracerEventType EvtType = TracerEventType::Type // NOLINT
} // namespace mdb
namespace fmt {

template <> struct formatter<mdb::TracerEventType>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const mdb::TracerEventType &evt, FormatContext &ctx) const
  {
    using enum mdb::TracerEventType;
    switch (evt) {
    case Stop:
      return fmt::format_to(ctx.out(), "TracerEventType::Stop");
    case LibraryEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::LibraryEvent");
    case BreakpointHitEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::BreakpointHitEvent");
    case SyscallEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::SyscallEvent");
    case ThreadCreated:
      return fmt::format_to(ctx.out(), "TracerEventType::ThreadCreated");
    case ThreadExited:
      return fmt::format_to(ctx.out(), "TracerEventType::ThreadExited");
    case WatchpointEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::WatchpointEvent");
    case ProcessExited:
      return fmt::format_to(ctx.out(), "TracerEventType::ProcessExited");
    case ProcessTerminated:
      return fmt::format_to(ctx.out(), "TracerEventType::ProcessTerminated");
    case Fork:
      return fmt::format_to(ctx.out(), "TracerEventType::Fork");
    case VFork:
      return fmt::format_to(ctx.out(), "TracerEventType::VFork");
    case VForkDone:
      return fmt::format_to(ctx.out(), "TracerEventType::VForkDone");
    case Exec:
      return fmt::format_to(ctx.out(), "TracerEventType::Exec");
    case Clone:
      return fmt::format_to(ctx.out(), "TracerEventType::Clone");
    case DeferToSupervisor:
      return fmt::format_to(ctx.out(), "TracerEventType::DeferToProceed");
    case Signal:
      return fmt::format_to(ctx.out(), "TracerEventType::Signal");
    case Stepped:
      return fmt::format_to(ctx.out(), "TracerEventType::Stepped");
    case Entry:
      return fmt::format_to(ctx.out(), "TracerEventType::Entry");
    }
    NEVER("Unknown Core event type");
  }
};

} // namespace fmt
namespace mdb {
struct TaskEvent
{
  Tid mThreadId;
};

struct WatchpointEvent : public TaskEvent
{
  EventType(WatchpointEvent);
  enum class WatchpointType
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
  tc::ResumeAction mResumeAction;
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
  std::optional<TaskVMInfo> mTaskStackMetadata;
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
  std::optional<mdb::LocationStatus> mLocationStatus;
  std::optional<tc::ResumeAction> mResumeWhenDone{};
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

using CoreEventVariant =
  std::variant<WatchpointEvent, SyscallEvent, ThreadCreated, ThreadExited, BreakpointHitEvent, ForkEvent, Clone,
               Exec, ProcessExited, LibraryEvent, Signal, Stepped, DeferToSupervisor, EntryEvent>;

/**
 * Core events are events generated by the the debugger core
 * It can be wait status events that has been massaged into core events, or it can be direct core events when they
 * come from a remote (via gdb remote protocol, see for instance 'stop reason' on stop replies)
 */
struct TraceEvent
{
  // The process for which this core event was generated for
  Immutable<Pid> mProcessId{0};
  // The thread for which this core event was generated for
  Immutable<Tid> mTaskId{0};
  // The payload std::variant, which holds the data and therefore determines what kind of event this is
  Immutable<CoreEventVariant> mEvent;
  // The signal generated (or the exit code returned) by the process that generated the
  Immutable<TracerEventType> mEventType;
  Immutable<int> mEventTime;
  union
  {
    int uSignal;
    int uExitCode;
  };
  // Potential thread's register contents. When dealing with GDB Remote protocol, it can actually
  // pass some of the register contents along with it's "stop replies" (basically events that is equivalent to
  // result of the syscall waitpid(...)). If the target is native, this will always be empty.
  Immutable<RegisterData> mRegisterData{};

  TraceEvent(int event_time, Pid target, Tid tid, CoreEventVariant &&p, TracerEventType type, int sig_code,
             RegisterData &&regs) noexcept;

  TraceEvent(const EventDataParam &param, CoreEventVariant &&p, TracerEventType type,
             RegisterData &&regs) noexcept;

  static TraceEvent *CreateLibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept;
  static TraceEvent *CreateSoftwareBreakpointHit(const EventDataParam &param,
                                                 std::optional<std::uintptr_t> address,
                                                 RegisterData &&reg) noexcept;
  static TraceEvent *CreateHardwareBreakpointHit(const EventDataParam &param,
                                                 std::optional<std::uintptr_t> address,
                                                 RegisterData &&reg) noexcept;
  static TraceEvent *CreateSyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static TraceEvent *CreateSyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static TraceEvent *CreateThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action,
                                         RegisterData &&reg) noexcept;
  static TraceEvent *CreateThreadExited(const EventDataParam &param, bool process_needs_resuming,
                                        RegisterData &&reg) noexcept;
  static TraceEvent *CreateWriteWatchpoint(const EventDataParam &param, std::uintptr_t addr,
                                           RegisterData &&reg) noexcept;
  static TraceEvent *CreateReadWatchpoint(const EventDataParam &param, std::uintptr_t addr,
                                          RegisterData &&reg) noexcept;
  static TraceEvent *CreateAccessWatchpoint(const EventDataParam &param, std::uintptr_t addr,
                                            RegisterData &&reg) noexcept;
  static TraceEvent *CreateForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept;
  static TraceEvent *CreateVForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept;
  static TraceEvent *CreateCloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                                      RegisterData &&reg) noexcept;
  static TraceEvent *CreateExecEvent(const EventDataParam &param, std::string_view exec_file,
                                     RegisterData &&reg) noexcept;
  static TraceEvent *CreateProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept;
  static TraceEvent *CreateSignal(const EventDataParam &param, RegisterData &&reg) noexcept;
  static TraceEvent *CreateStepped(const EventDataParam &param, bool stop,
                                   std::optional<mdb::LocationStatus> bploc,
                                   std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept;
  static TraceEvent *CreateSteppingDone(const EventDataParam &param, std::string_view msg,
                                        RegisterData &&reg) noexcept;
  static TraceEvent *CreateDeferToSupervisor(const EventDataParam &param, RegisterData &&reg,
                                             bool attached) noexcept;
  static TraceEvent *CreateEntryEvent(const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept;
};

enum class InternalEventDiscriminant
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
  TraceeController *mSupervisor;
};

struct TerminateDebugging
{
};

struct InitializedWaitSystem
{
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
  EventType mEventType;
  union
  {
    WaitEvent uWait;
    TraceEvent *uDebugger;
    ui::UICommand *uCommand;
    InternalEvent uInternalEvent;
  };

  constexpr explicit ApplicationEvent(ui::UICommand *command) noexcept
      : mEventType(EventType::Command), uCommand(command)
  {
  }
  constexpr explicit ApplicationEvent(TraceEvent *debuggerEvent, bool isInit = false) noexcept
      : mEventType(!isInit ? EventType::TraceeEvent : EventType::Initialization), uDebugger(debuggerEvent)
  {
  }
  constexpr explicit ApplicationEvent(WaitEvent waitEvent) noexcept
      : mEventType(EventType::WaitStatus), uWait(waitEvent)
  {
  }
  constexpr explicit ApplicationEvent(InternalEvent internalEvent) noexcept
      : mEventType(EventType::Internal), uInternalEvent(internalEvent)
  {
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
  int mCommandEvents[2];
  int mDebuggerEvents[2];
  int mInitEvents[2];
  int mInternalEvents[2];
  int mSignalFd;

  int mCurrentPollDescriptors;
  pollfd mPollDescriptors[5];

  std::mutex mCommandsGuard{};
  std::mutex mTraceEventGuard{};
  std::mutex mInternalEventGuard{};
  std::vector<TraceEvent *> mTraceEvents;
  std::vector<ui::UICommand *> mCommands;
  std::vector<ApplicationEvent> mWaitEvents;
  std::vector<TraceEvent *> mInitEvent;
  std::vector<InternalEvent> mInternal;
  EventSystem(int commands[2], int debugger[2], int init[2], int internal[2]) noexcept;

  static EventSystem *sEventSystem;

  int mPollFailures = 0;

  int PollDescriptorsCount() const noexcept;

public:
  static EventSystem *Initialize() noexcept;
  void InitWaitStatusManager() noexcept;
  void PushCommand(ui::dap::DebugAdapterClient *dap_client, ui::UICommand *cmd) noexcept;
  void PushDebuggerEvent(TraceEvent *event) noexcept;
  void ConsumeDebuggerEvents(std::vector<TraceEvent *> &events) noexcept;
  void PushInitEvent(TraceEvent *event) noexcept;
  void NotifyNewWaitpidResults() noexcept;
  void PushInternalEvent(InternalEvent event) noexcept;
  bool PollBlocking(std::vector<ApplicationEvent> &write) noexcept;

  static EventSystem &Get() noexcept;
};
} // namespace mdb
// NOLINTEND(cppcoreguidelines-owning-memory)