/** LICENSE TEMPLATE */
#pragma once

#include "event_queue_event_param.h"
#include "task.h"
#include <mdbsys/ptrace.h>
#include <string>
#include <sys/poll.h>
#include <variant>

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
  TaskWaitResult wait;
  int core;
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
#define LogEvent(EventObject, Msg)                                                                                \
  DBGLOG(core, "[Core Event:{}.{}] ({}): {}", mTaskLeader, task ? task->mTid : 0, EventObject.event_type, Msg) // NOLINT

namespace fmt {

template <> struct formatter<TracerEventType>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const TracerEventType &evt, FormatContext &ctx) const
  {
    switch (evt) {
    case TracerEventType::Stop:
      return fmt::format_to(ctx.out(), "TracerEventType::Stop");
    case TracerEventType::LibraryEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::LibraryEvent");
    case TracerEventType::BreakpointHitEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::BreakpointHitEvent");
    case TracerEventType::SyscallEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::SyscallEvent");
    case TracerEventType::ThreadCreated:
      return fmt::format_to(ctx.out(), "TracerEventType::ThreadCreated");
    case TracerEventType::ThreadExited:
      return fmt::format_to(ctx.out(), "TracerEventType::ThreadExited");
    case TracerEventType::WatchpointEvent:
      return fmt::format_to(ctx.out(), "TracerEventType::WatchpointEvent");
    case TracerEventType::ProcessExited:
      return fmt::format_to(ctx.out(), "TracerEventType::ProcessExited");
    case TracerEventType::ProcessTerminated:
      return fmt::format_to(ctx.out(), "TracerEventType::ProcessTerminated");
    case TracerEventType::Fork:
      return fmt::format_to(ctx.out(), "TracerEventType::Fork");
    case TracerEventType::VFork:
      return fmt::format_to(ctx.out(), "TracerEventType::VFork");
    case TracerEventType::VForkDone:
      return fmt::format_to(ctx.out(), "TracerEventType::VForkDone");
    case TracerEventType::Exec:
      return fmt::format_to(ctx.out(), "TracerEventType::Exec");
    case TracerEventType::Clone:
      return fmt::format_to(ctx.out(), "TracerEventType::Clone");
    case TracerEventType::DeferToSupervisor:
      return fmt::format_to(ctx.out(), "TracerEventType::DeferToProceed");
    case TracerEventType::Signal:
      return fmt::format_to(ctx.out(), "TracerEventType::Signal");
    case TracerEventType::Stepped:
      return fmt::format_to(ctx.out(), "TracerEventType::Stepped");
    case TracerEventType::Entry:
      return fmt::format_to(ctx.out(), "TracerEventType::Entry");
    }
    NEVER("Unknown Core event type");
  }
};

} // namespace fmt

struct TaskEvent
{
  Tid thread_id;
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

  WatchpointType type;
  std::uintptr_t address;
};

struct SyscallEvent : public TaskEvent
{
  EventType(SyscallEvent);
  enum class Boundary : u8
  {
    Entry,
    Exit
  };

  Boundary boundary;
  int syscall_no;
};

struct ThreadCreated : public TaskEvent
{
  EventType(ThreadCreated);
  tc::ResumeAction resume_action;
};

struct ThreadExited : public TaskEvent
{
  EventType(ThreadExited);
  int code_or_signal;
  bool process_needs_resuming;
};

struct ForkEvent : public TaskEvent
{
  EventType(Fork);
  Pid child_pid;
  bool mIsVFork;
};

struct Clone : public TaskEvent
{
  EventType(Clone);
  Tid child_tid;
  std::optional<TaskVMInfo> vm_info;
};

struct Exec : public TaskEvent
{
  EventType(Exec);
  std::string exec_file;
};

struct ProcessExited : public TaskEvent
{
  EventType(ProcessExited);
  Pid pid;
  int exit_code;
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
  bool stop;
  std::optional<LocationStatus> loc_stat;
  std::optional<tc::ResumeAction> resume_when_done{};
  std::string_view msg{};
};

struct BreakpointHitEvent : public TaskEvent
{
  EventType(BreakpointHitEvent);
  enum class BreakpointType : u8
  {
    Software,
    Hardware
  };

  Immutable<BreakpointType> type;
  Immutable<std::optional<std::uintptr_t>> address_val;
};

// A never-facing-user event. used to signal that a proceed action is solely responsible for determining the next
// action of a task
struct DeferToSupervisor : public TaskEvent
{
  EventType(DeferToSupervisor);
  bool attached;
};

struct EntryEvent : public TaskEvent
{
  EventType(Entry);
  bool should_stop;
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
  Immutable<Pid> target{0};
  // The thread for which this core event was generated for
  Immutable<Tid> tid{0};
  // The payload std::variant, which holds the data and therefore determines what kind of event this is
  Immutable<CoreEventVariant> event;
  // The signal generated (or the exit code returned) by the process that generated the
  Immutable<TracerEventType> event_type;
  union
  {
    int signal;
    int exit_code;
  };
  // Potential thread's register contents. When dealing with GDB Remote protocol, it can actually
  // pass some of the register contents along with it's "stop replies" (basically events that is equivalent to
  // result of the syscall waitpid(...)). If the target is native, this will always be empty.
  Immutable<RegisterData> registers{};

  TraceEvent(Pid target, Tid tid, CoreEventVariant &&p, TracerEventType type, int sig_code,
             RegisterData &&regs) noexcept;

  TraceEvent(const EventDataParam &param, CoreEventVariant &&p, TracerEventType type,
             RegisterData &&regs) noexcept;

  static TraceEvent *LibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept;
  static TraceEvent *SoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> address,
                                           RegisterData &&reg) noexcept;
  static TraceEvent *HardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> address,
                                           RegisterData &&reg) noexcept;
  static TraceEvent *SyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static TraceEvent *SyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static TraceEvent *ThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action,
                                   RegisterData &&reg) noexcept;
  static TraceEvent *ThreadExited(const EventDataParam &param, bool process_needs_resuming,
                                  RegisterData &&reg) noexcept;
  static TraceEvent *WriteWatchpoint(const EventDataParam &param, std::uintptr_t addr,
                                     RegisterData &&reg) noexcept;
  static TraceEvent *ReadWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept;
  static TraceEvent *AccessWatchpoint(const EventDataParam &param, std::uintptr_t addr,
                                      RegisterData &&reg) noexcept;
  static TraceEvent *ForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept;
  static TraceEvent *VForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept;
  static TraceEvent *CloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                                RegisterData &&reg) noexcept;
  static TraceEvent *ExecEvent(const EventDataParam &param, std::string_view exec_file,
                               RegisterData &&reg) noexcept;
  static TraceEvent *ProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept;
  static TraceEvent *Signal(const EventDataParam &param, RegisterData &&reg) noexcept;
  static TraceEvent *Stepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> bploc,
                             std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept;
  static TraceEvent *SteppingDone(const EventDataParam &param, std::string_view msg, RegisterData &&reg) noexcept;
  static TraceEvent *DeferToSupervisor(const EventDataParam &param, RegisterData &&reg, bool attached) noexcept;
  static TraceEvent *EntryEvent(const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept;
};

enum class InternalEventDiscriminant
{
  InvalidateSupervisor,
  TerminateDebugging,
};

// Event sent when a supervisor for a process "dies". Was called "DestroySupervisor" before
// but seeing as the plan is to integrate with RR at some point, it's better to just call it "invalidate" instead
// so that it can be potentially lifted back into life, if the user reverse-continues across the boundary of it's normal death.
struct InvalidateSupervisor
{
  TraceeController* mSupervisor;
};

struct TerminateDebugging {};

struct InternalEvent
{
  InternalEvent() noexcept = delete;
  InternalEvent(const InternalEvent&) noexcept = default;
  InternalEvent& operator=(const InternalEvent&) noexcept = default;

  union
  {
    InvalidateSupervisor uInvalidateSupervisor;
    TerminateDebugging uTerminateDebugging;
  };
  InternalEventDiscriminant mType;

  UnionVariantConstructor(InternalEvent, InvalidateSupervisor)
  UnionVariantConstructor(InternalEvent, TerminateDebugging)
};

struct Event
{
  EventType type;
  union
  {
    WaitEvent uWait;
    TraceEvent *uDebugger;
    ui::UICommand *uCommand;
    InternalEvent uInternalEvent;
  };

  constexpr explicit Event(ui::UICommand *command) noexcept : type(EventType::Command), uCommand(command) {}
  constexpr explicit Event(TraceEvent *debuggerEvent, bool isInit = false) noexcept
      : type(!isInit ? EventType::TraceeEvent : EventType::Initialization), uDebugger(debuggerEvent)
  {
  }
  constexpr explicit Event(WaitEvent waitEvent) noexcept : type(EventType::WaitStatus), uWait(waitEvent) {}
  constexpr explicit Event(InternalEvent internalEvent) noexcept
      : type(EventType::Internal), uInternalEvent(internalEvent)
  {
  }
};

/// Result from a (successful) waitpid operation.
/// This type is serialized over a pipe from either signal handler (handling SIGCHLD as a tracer-method), or from
/// an awaiter thread, that does infinite waitpid(...)
struct WaitResult
{
  pid_t pid;
  int stat;
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
  int mWaitStatus[2];
  int mCommandEvents[2];
  int mDebuggerEvents[2];
  int mInitEvents[2];
  int mInternalEvents[2];

  pollfd mPollDescriptors[5];

  std::mutex mCommandsGuard{};
  std::mutex mTraceEventGuard{};
  std::mutex mInternalEventGuard{};
  std::vector<TraceEvent *> mTraceEvents;
  std::vector<ui::UICommand *> mCommands;
  std::vector<Event> mWaitEvents;
  std::vector<TraceEvent *> mInitEvent;
  std::vector<InternalEvent> mInternal;
  EventSystem(int wait[2], int commands[2], int debugger[2], int init[2], int internal[2]) noexcept;

  static EventSystem *sEventSystem;

  int mPollFailures = 0;

public:
  static EventSystem *Initialize() noexcept;
  void PushCommand(ui::dap::DebugAdapterClient *dap_client, ui::UICommand *cmd) noexcept;
  void PushDebuggerEvent(TraceEvent *event) noexcept;
  void ConsumeDebuggerEvents(std::vector<TraceEvent *> &events) noexcept;
  void PushInitEvent(TraceEvent *event) noexcept;
  void PushWaitResult(WaitResult result) noexcept;
  void NotifyNewWaitpidResults() noexcept;
  void PushReapedWaitResults(std::span<WaitResult> results) noexcept;
  void PushInternalEvent(InternalEvent event) noexcept;
  bool PollBlocking(std::vector<Event> &write) noexcept;

  static EventSystem &Get() noexcept;
};

// NOLINTEND(cppcoreguidelines-owning-memory)