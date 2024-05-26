#include "event_queue.h"
#include "bp.h"
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>

// todo(simon): Major refactor. This file is just a proto-prototype event queue system, to replace the more hacky
// system that was before.

static std::mutex event_queue_mutex{};
static std::mutex event_queue_wait_mutex{};
static std::condition_variable cv{};
static std::queue<Event> events{};

CoreEvent::CoreEvent(Pid target, Tid tid, CoreEventVariant &&p, CoreEventType type, int sig_code,
                     RegisterData &&reg) noexcept
    : target(target), tid(tid), event(std::move(p)), event_type(type), signal(sig_code), registers(std::move(reg))
{
}

CoreEvent::CoreEvent(const EventDataParam &param, CoreEventVariant &&p, CoreEventType type,
                     RegisterData &&regs) noexcept
    : CoreEvent{param.target,   param.tid.value(), std::move(p), type, param.sig_or_code.value_or(0),
                std::move(regs)}
{
}

CoreEvent *
CoreEvent::LibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event LibraryEvent");
  return new CoreEvent{param, ::LibraryEvent{param.tid.value_or(param.target)}, CoreEventType::LibraryEvent,
                       std::move(reg)};
}
CoreEvent *
CoreEvent::SoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                 RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event SoftwareBreakpointHit");
  return new CoreEvent{
      param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Software, addr},
      CoreEventType::BreakpointHitEvent, std::move(reg)};
}

CoreEvent *
CoreEvent::HardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                 RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event HardwareBreakpointHit");
  return new CoreEvent{
      param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Hardware, addr},
      CoreEventType::BreakpointHitEvent, std::move(reg)};
}

CoreEvent *
CoreEvent::SyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event SyscallEntry");
  return new CoreEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Entry, syscall},
                       CoreEventType::SyscallEvent, std::move(reg)};
}
CoreEvent *
CoreEvent::SyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event SyscallExit");
  return new CoreEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Exit, syscall},
                       CoreEventType::SyscallEvent, std::move(reg)};
}

CoreEvent *
CoreEvent::ThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ThreadCreated");
  return new CoreEvent{param, ::ThreadCreated{{param.tid.value_or(-1)}, resume_action},
                       CoreEventType::ThreadCreated, std::move(reg)};
}
CoreEvent *
CoreEvent::ThreadExited(const EventDataParam &param, bool process_needs_resuming, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ThreadExited");
  return new CoreEvent{
      param, ::ThreadExited{{param.tid.value_or(-1)}, param.sig_or_code.value_or(-1), process_needs_resuming},
      CoreEventType::ThreadExited, std::move(reg)};
}

CoreEvent *
CoreEvent::WriteWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event WriteWatchpoint");
  return new CoreEvent{
      param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Write, addr},
      CoreEventType::WatchpointEvent, std::move(reg)};
}
CoreEvent *
CoreEvent::ReadWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ReadWatchpoint");
  return new CoreEvent{
      param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Read, addr},
      CoreEventType::WatchpointEvent, std::move(reg)};
}
CoreEvent *
CoreEvent::AccessWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event AccessWatchpoint");
  return new CoreEvent{
      param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Access, addr},
      CoreEventType::WatchpointEvent, std::move(reg)};
}

CoreEvent *
CoreEvent::ForkEvent(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ForkEvent");
  return new CoreEvent{param, Fork{{param.target}, new_pid}, CoreEventType::Fork, std::move(reg)};
}

CoreEvent *
CoreEvent::CloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                      RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event CloneEvent");
  return new CoreEvent{param, Clone{{param.target}, new_tid, vm_info}, CoreEventType::Clone, std::move(reg)};
}

CoreEvent *
CoreEvent::ExecEvent(const EventDataParam &param, std::string_view exec_file, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ExecEvent");
  return new CoreEvent{param, Exec{{param.target}, std::string{exec_file}}, CoreEventType::Exec, std::move(reg)};
}

CoreEvent *
CoreEvent::ProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ProcessExitEvent");
  return new CoreEvent{pid,       tid,           ProcessExited{{tid}, pid}, CoreEventType::ProcessExited,
                       exit_code, std::move(reg)};
}

CoreEvent *
CoreEvent::Signal(const EventDataParam &param, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event Signal");
  return new CoreEvent{param, ::Signal{{param.target}}, CoreEventType::Signal, std::move(reg)};
}

CoreEvent *
CoreEvent::Stepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> bploc,
                   std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event Stepped");
  return new CoreEvent{param, ::Stepped{{param.tid.value()}, stop, bploc, mayresume}, CoreEventType::Stepped,
                       std::move(reg)};
}

CoreEvent *
CoreEvent::DeferToSupervisor(const EventDataParam &param, RegisterData &&reg, bool attached) noexcept
{
  DBGLOG(core, "[Core Event]: creating event DeferToSupervisor");
  return new CoreEvent{param, ::DeferToSupervisor{{param.tid.value()}, attached}, CoreEventType::DeferToSupervisor,
                       std::move(reg)};
}

static void
push_event(Event e)
{
  std::lock_guard lock(event_queue_mutex);
  events.push(e);
  cv.notify_all();
}

void
push_wait_event(Tid process_group, TaskWaitResult wait_result) noexcept
{
  push_event(Event{.type = EventType::WaitStatus, .wait = {.process_group = process_group, .wait = wait_result}});
}

void
push_command_event(ui::UICommand *cmd) noexcept
{
  push_event(Event{.type = EventType::Command, .cmd = cmd});
}

void
push_debugger_event(CoreEvent *event) noexcept
{
  push_event(Event{.type = EventType::DebuggerEvent, .debugger = event});
}

void
push_init_event(CoreEvent *event) noexcept
{
  push_event(Event{.type = EventType::Initialization, .debugger = event});
}

Event
poll_event()
{
  while (events.empty()) {
    std::unique_lock lock(event_queue_wait_mutex);
    cv.wait_for(lock, std::chrono::milliseconds{10});
  }

  Event evt;
  {
    std::lock_guard lock(event_queue_mutex);
    // Todo: implement own queue, that instead of this atrocity, has a pop(), that also returns the value
    evt = events.front();
    events.pop();
  }
  return evt;
}