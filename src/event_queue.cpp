#include "event_queue.h"
#include <chrono>
#include <condition_variable>
#include <interface/ui_command.h>
#include <mutex>
#include <optional>
#include <queue>

// todo(simon): Major refactor. This file is just a proto-prototype event queue system, to replace the more hacky
// system that was before.

static std::mutex event_queue_mutex{};
static std::mutex event_queue_wait_mutex{};
static std::condition_variable cv{};
static std::queue<Event> events{};

#define CORE_EVENT_LOG(fmtstring, ...)                                                                            \
  DBGLOG(core, "[{} event {}:{}]: " fmtstring, __FUNCTION__, param.target,                                        \
         param.tid.value_or(-1) __VA_OPT__(, ) __VA_ARGS__)

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
TraceEvent::TraceEvent(Pid target, Tid tid, CoreEventVariant &&p, CoreEventType type, int sig_code,
                     RegisterData &&reg) noexcept
    : target(target), tid(tid), event(std::move(p)), event_type(type), signal(sig_code), registers(std::move(reg))
{
}

TraceEvent::TraceEvent(const EventDataParam &param, CoreEventVariant &&p, CoreEventType type,
                     RegisterData &&regs) noexcept
    : TraceEvent{param.target,   param.tid.value(), std::move(p), type, param.sig_or_code.value_or(0),
                std::move(regs)}
{
}

TraceEvent *
TraceEvent::LibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event LibraryEvent");
  return new TraceEvent{param, ::LibraryEvent{param.tid.value_or(param.target)}, CoreEventType::LibraryEvent,
                       std::move(reg)};
}
TraceEvent *
TraceEvent::SoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                 RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SoftwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Software, addr},
    CoreEventType::BreakpointHitEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::HardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                 RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event HardwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Hardware, addr},
    CoreEventType::BreakpointHitEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::SyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SyscallEntry");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Entry, syscall},
                       CoreEventType::SyscallEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::SyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SyscallExit");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Exit, syscall},
                       CoreEventType::SyscallEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::ThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ThreadCreated");
  return new TraceEvent{param, ::ThreadCreated{{param.tid.value_or(-1)}, resume_action},
                       CoreEventType::ThreadCreated, std::move(reg)};
}
TraceEvent *
TraceEvent::ThreadExited(const EventDataParam &param, bool process_needs_resuming, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ThreadExited for pid={},tid={}", param.target, param.tid.value_or(-1));
  return new TraceEvent{
    param, ::ThreadExited{{param.tid.value_or(-1)}, param.sig_or_code.value_or(-1), process_needs_resuming},
    CoreEventType::ThreadExited, std::move(reg)};
}

TraceEvent *
TraceEvent::WriteWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event WriteWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Write, addr},
    CoreEventType::WatchpointEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::ReadWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ReadWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Read, addr},
    CoreEventType::WatchpointEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::AccessWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event AccessWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Access, addr},
    CoreEventType::WatchpointEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::ForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  return new TraceEvent{param, ForkEvent{{param.target}, new_pid}, CoreEventType::Fork, std::move(reg)};
}

/* static */
TraceEvent *
TraceEvent::VForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  return new TraceEvent{param, ForkEvent{{.thread_id = param.target}, new_pid, true}, CoreEventType::VFork,
                       std::move(reg)};
}

TraceEvent *
TraceEvent::CloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                      RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event CloneEvent, new task: {}", new_tid);
  return new TraceEvent{param, Clone{{param.target}, new_tid, vm_info}, CoreEventType::Clone, std::move(reg)};
}

TraceEvent *
TraceEvent::ExecEvent(const EventDataParam &param, std::string_view exec_file, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ExecEvent");
  return new TraceEvent{param, Exec{{param.target}, std::string{exec_file}}, CoreEventType::Exec, std::move(reg)};
}

TraceEvent *
TraceEvent::ProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ProcessExitEvent for {}:{}", pid, tid);
  return new TraceEvent{
    pid, tid, ProcessExited{{tid}, pid, exit_code}, CoreEventType::ProcessExited, exit_code, std::move(reg)};
}

TraceEvent *
TraceEvent::Signal(const EventDataParam &param, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event Signal");
  return new TraceEvent{param, ::Signal{{param.target}}, CoreEventType::Signal, std::move(reg)};
}

TraceEvent *
TraceEvent::Stepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> bploc,
                   std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event Stepped");
  return new TraceEvent{param, ::Stepped{{param.tid.value()}, stop, bploc, mayresume}, CoreEventType::Stepped,
                       std::move(reg)};
}

TraceEvent *
TraceEvent::SteppingDone(const EventDataParam &param, std::string_view msg, RegisterData &&reg) noexcept
{
  return new TraceEvent{param, ::Stepped{{param.tid.value()}, true, {}, {}, msg}, CoreEventType::Stepped,
                       std::move(reg)};
}

TraceEvent *
TraceEvent::DeferToSupervisor(const EventDataParam &param, RegisterData &&reg, bool attached) noexcept
{
  CORE_EVENT_LOG("creating event DeferToSupervisor");
  return new TraceEvent{param, ::DeferToSupervisor{{param.tid.value()}, attached}, CoreEventType::DeferToSupervisor,
                       std::move(reg)};
}

TraceEvent *
TraceEvent::EntryEvent(const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept
{
  CORE_EVENT_LOG("creating event DeferToSupervisor");
  return new TraceEvent{param, ::EntryEvent{{param.tid.value()}, should_stop}, CoreEventType::Entry,
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
push_wait_event(TaskWaitResult wait_result) noexcept
{
  push_event(Event{.type = EventType::WaitStatus, .wait = {.wait = wait_result, .core = 0}});
}

void
push_command_event(ui::dap::DebugAdapterClient *dap, ui::UICommand *cmd) noexcept
{
  cmd->SetDebugAdapterClient(*dap);
  push_event(Event{.type = EventType::Command, .cmd = cmd});
}

void
push_debugger_event(TraceEvent *event) noexcept
{
  push_event(Event{.type = EventType::TraceeEvent, .debugger = event});
}

void
push_init_event(TraceEvent *event) noexcept
{
  push_event(Event{.type = EventType::Initialization, .debugger = event});
}

Event
poll_event()
{
  constexpr static auto SLEEP_CYCLE = 10;
  while (events.empty()) {
    std::unique_lock lock(event_queue_wait_mutex);
    cv.wait_for(lock, std::chrono::milliseconds{SLEEP_CYCLE});
  }

  std::lock_guard lock(event_queue_mutex);
  // Todo: implement own queue, that instead of this atrocity, has a pop(), that also returns the value
  Event evt = events.front();
  events.pop();
  return evt;
}
// NOLINTEND(cppcoreguidelines-owning-memory)