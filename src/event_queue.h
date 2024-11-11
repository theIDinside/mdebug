#pragma once

#include "bp.h"
#include "event_queue_event_param.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "ptrace.h"
#include "task.h"
#include <string>
#include <utility>
#include <variant>
#include <vector>

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
  DebuggerEvent,
  Initialization
};

struct WaitEvent
{
  Tid process_group;
  TaskWaitResult wait;
  int core;
};

enum class CoreEventType
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

#define EventType(Type) static constexpr CoreEventType EvtType = CoreEventType::Type
#define LogEvent(EventObject, Msg) DBGLOG(core, "[Core Event] ({}): {}", EventObject.event_type, Msg)

namespace fmt {

template <> struct formatter<CoreEventType>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const CoreEventType &evt, FormatContext &ctx) const
  {
    switch (evt) {
    case CoreEventType::Stop:
      return fmt::format_to(ctx.out(), "CoreEventType::Stop");
    case CoreEventType::LibraryEvent:
      return fmt::format_to(ctx.out(), "CoreEventType::LibraryEvent");
    case CoreEventType::BreakpointHitEvent:
      return fmt::format_to(ctx.out(), "CoreEventType::BreakpointHitEvent");
    case CoreEventType::SyscallEvent:
      return fmt::format_to(ctx.out(), "CoreEventType::SyscallEvent");
    case CoreEventType::ThreadCreated:
      return fmt::format_to(ctx.out(), "CoreEventType::ThreadCreated");
    case CoreEventType::ThreadExited:
      return fmt::format_to(ctx.out(), "CoreEventType::ThreadExited");
    case CoreEventType::WatchpointEvent:
      return fmt::format_to(ctx.out(), "CoreEventType::WatchpointEvent");
    case CoreEventType::ProcessExited:
      return fmt::format_to(ctx.out(), "CoreEventType::ProcessExited");
    case CoreEventType::ProcessTerminated:
      return fmt::format_to(ctx.out(), "CoreEventType::ProcessTerminated");
    case CoreEventType::Fork:
      return fmt::format_to(ctx.out(), "CoreEventType::Fork");
    case CoreEventType::VFork:
      return fmt::format_to(ctx.out(), "CoreEventType::VFork");
    case CoreEventType::VForkDone:
      return fmt::format_to(ctx.out(), "CoreEventType::VForkDone");
    case CoreEventType::Exec:
      return fmt::format_to(ctx.out(), "CoreEventType::Exec");
    case CoreEventType::Clone:
      return fmt::format_to(ctx.out(), "CoreEventType::Clone");
    case CoreEventType::DeferToSupervisor:
      return fmt::format_to(ctx.out(), "CoreEventType::DeferToProceed");
    case CoreEventType::Signal:
      return fmt::format_to(ctx.out(), "CoreEventType::Signal");
    case CoreEventType::Stepped:
      return fmt::format_to(ctx.out(), "CoreEventType::Stepped");
    case CoreEventType::Entry:
      return fmt::format_to(ctx.out(), "CoreEventType::Entry");
    }
    NEVER("Unknown Core event type");
  }
};

} // namespace fmt

struct ThreadEvent
{
  Tid thread_id;
};

struct WatchpointEvent : public ThreadEvent
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

struct SyscallEvent : public ThreadEvent
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

struct ThreadCreated : public ThreadEvent
{
  EventType(ThreadCreated);
  tc::ResumeAction resume_action;
};

struct ThreadExited : public ThreadEvent
{
  EventType(ThreadExited);
  int code_or_signal;
  bool process_needs_resuming;
};

struct Fork : public ThreadEvent
{
  EventType(Fork);
  Pid child_pid;
};

struct Clone : public ThreadEvent
{
  EventType(Clone);
  Tid child_tid;
  std::optional<TaskVMInfo> vm_info;
};

struct Exec : public ThreadEvent
{
  EventType(Exec);
  std::string exec_file;
};

struct ProcessExited : public ThreadEvent
{
  EventType(ProcessExited);
  Pid pid;
  int exit_code;
};

struct LibraryEvent : public ThreadEvent
{
  EventType(LibraryEvent);
};

struct Signal : public ThreadEvent
{
  EventType(Signal);
};

struct Stepped : public ThreadEvent
{
  EventType(Stepped);
  bool stop;
  std::optional<LocationStatus> loc_stat;
  std::optional<tc::ResumeAction> resume_when_done{};
  std::string_view msg{};
};

struct BreakpointHitEvent : public ThreadEvent
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
struct DeferToSupervisor : public ThreadEvent
{
  EventType(DeferToSupervisor);
  bool attached;
};

struct EntryEvent : public ThreadEvent
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
  std::variant<WatchpointEvent, SyscallEvent, ThreadCreated, ThreadExited, BreakpointHitEvent, Fork, Clone, Exec,
               ProcessExited, LibraryEvent, Signal, Stepped, DeferToSupervisor, EntryEvent>;

/**
 * Core events are events generated by the the debugger core
 * It can be wait status events that has been massaged into core events, or it can be direct core events when they
 * come from a remote (via gdb remote protocol, see for instance 'stop reason' on stop replies)
 */
struct CoreEvent
{
  // The process for which this core event was generated for
  Immutable<Pid> target{0};
  // The thread for which this core event was generated for
  Immutable<Tid> tid{0};
  // The payload std::variant, which holds the data and therefore determines what kind of event this is
  Immutable<CoreEventVariant> event;
  // The signal generated (or the exit code returned) by the process that generated the
  Immutable<CoreEventType> event_type;
  union
  {
    int signal;
    int exit_code;
  };
  // Potential thread's register contents. When dealing with GDB Remote protocol, it can actually
  // pass some of the register contents along with it's "stop replies" (basically events that is equivalent to
  // result of the syscall waitpid(...)). If the target is native, this will always be empty.
  Immutable<RegisterData> registers{};

  CoreEvent(Pid target, Tid tid, CoreEventVariant &&p, CoreEventType type, int sig_code,
            RegisterData &&regs) noexcept;

  CoreEvent(const EventDataParam &param, CoreEventVariant &&p, CoreEventType type, RegisterData &&regs) noexcept;

  static CoreEvent *LibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept;
  static CoreEvent *SoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> address,
                                          RegisterData &&reg) noexcept;
  static CoreEvent *HardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> address,
                                          RegisterData &&reg) noexcept;
  static CoreEvent *SyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static CoreEvent *SyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept;
  static CoreEvent *ThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action,
                                  RegisterData &&reg) noexcept;
  static CoreEvent *ThreadExited(const EventDataParam &param, bool process_needs_resuming,
                                 RegisterData &&reg) noexcept;
  static CoreEvent *WriteWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept;
  static CoreEvent *ReadWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept;
  static CoreEvent *AccessWatchpoint(const EventDataParam &param, std::uintptr_t addr,
                                     RegisterData &&reg) noexcept;
  static CoreEvent *ForkEvent(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept;
  static CoreEvent *CloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                               RegisterData &&reg) noexcept;
  static CoreEvent *ExecEvent(const EventDataParam &param, std::string_view exec_file,
                              RegisterData &&reg) noexcept;
  static CoreEvent *ProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept;
  static CoreEvent *Signal(const EventDataParam &param, RegisterData &&reg) noexcept;
  static CoreEvent *Stepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> bploc,
                            std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept;
  static CoreEvent *SteppingDone(const EventDataParam &param, std::string_view msg, RegisterData &&reg) noexcept;
  static CoreEvent *DeferToSupervisor(const EventDataParam &param, RegisterData &&reg, bool attached) noexcept;
  static CoreEvent *EntryEvent(const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept;
};

struct Event
{
  EventType type;
  union
  {
    WaitEvent wait;
    CoreEvent *debugger;
    ui::UICommand *cmd;
  };
};

void push_wait_event(Tid process_group, TaskWaitResult wait_result) noexcept;
void push_command_event(ui::dap::DebugAdapterClient *dap_client, ui::UICommand *cmd) noexcept;
void push_debugger_event(CoreEvent *event) noexcept;
void push_init_event(CoreEvent *event) noexcept;

Event poll_event();