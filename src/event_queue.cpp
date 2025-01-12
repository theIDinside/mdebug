#include "event_queue.h"
#include "common.h"
#include "supervisor.h"
#include "tracer.h"
#include "utils/debug_value.h"
#include <cstring>
#include <fcntl.h>
#include <interface/ui_command.h>
#include <mutex>
#include <optional>
#include <ranges>

// todo(simon): Major refactor. This file is just a proto-prototype event queue system, to replace the more hacky
// system that was before.

EventSystem *EventSystem::sEventSystem = nullptr;

#define CORE_EVENT_LOG(fmtstring, ...)
// DBGLOG(core, "[{} event {}:{}]: " fmtstring, __FUNCTION__, param.target,
//  param.tid.value_or(-1) __VA_OPT__(, ) __VA_ARGS__)

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
TraceEvent::TraceEvent(Pid target, Tid tid, CoreEventVariant &&p, TracerEventType type, int sig_code,
                       RegisterData &&reg) noexcept
    : target(target), tid(tid), event(std::move(p)), event_type(type), signal(sig_code), registers(std::move(reg))
{
}

TraceEvent::TraceEvent(const EventDataParam &param, CoreEventVariant &&p, TracerEventType type,
                       RegisterData &&regs) noexcept
    : TraceEvent{param.target,   param.tid.value(), std::move(p), type, param.sig_or_code.value_or(0),
                 std::move(regs)}
{
}

TraceEvent *
TraceEvent::LibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event LibraryEvent");
  return new TraceEvent{param, ::LibraryEvent{param.tid.value_or(param.target)}, TracerEventType::LibraryEvent,
                        std::move(reg)};
}
TraceEvent *
TraceEvent::SoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                  RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SoftwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Software, addr},
    TracerEventType::BreakpointHitEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::HardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                  RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event HardwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Hardware, addr},
    TracerEventType::BreakpointHitEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::SyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SyscallEntry");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Entry, syscall},
                        TracerEventType::SyscallEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::SyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SyscallExit");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Exit, syscall},
                        TracerEventType::SyscallEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::ThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ThreadCreated");
  return new TraceEvent{param, ::ThreadCreated{{param.tid.value_or(-1)}, resume_action},
                        TracerEventType::ThreadCreated, std::move(reg)};
}
TraceEvent *
TraceEvent::ThreadExited(const EventDataParam &param, bool process_needs_resuming, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ThreadExited for pid={},tid={}", param.target, param.tid.value_or(-1));
  return new TraceEvent{
    param, ::ThreadExited{{param.tid.value_or(-1)}, param.sig_or_code.value_or(-1), process_needs_resuming},
    TracerEventType::ThreadExited, std::move(reg)};
}

TraceEvent *
TraceEvent::WriteWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event WriteWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Write, addr},
    TracerEventType::WatchpointEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::ReadWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ReadWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Read, addr},
    TracerEventType::WatchpointEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::AccessWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event AccessWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Access, addr},
    TracerEventType::WatchpointEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::ForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  return new TraceEvent{param, ForkEvent{{param.target}, new_pid}, TracerEventType::Fork, std::move(reg)};
}

/* static */
TraceEvent *
TraceEvent::VForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  ASSERT(param.tid.has_value(), "param must have tid value");
  return new TraceEvent{param, ForkEvent{{.thread_id = param.tid.value()}, new_pid, true}, TracerEventType::VFork,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                       RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event CloneEvent, new task: {}", new_tid);
  return new TraceEvent{param, Clone{{param.target}, new_tid, vm_info}, TracerEventType::Clone, std::move(reg)};
}

TraceEvent *
TraceEvent::ExecEvent(const EventDataParam &param, std::string_view exec_file, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ExecEvent");
  return new TraceEvent{param, Exec{{param.target}, std::string{exec_file}}, TracerEventType::Exec,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::ProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ProcessExitEvent for {}:{}", pid, tid);
  return new TraceEvent{
    pid, tid, ProcessExited{{tid}, pid, exit_code}, TracerEventType::ProcessExited, exit_code, std::move(reg)};
}

TraceEvent *
TraceEvent::Signal(const EventDataParam &param, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event Signal {}={}", param.sig_or_code.value_or(0),
                 param.sig_or_code.transform([](auto sig) -> std::string_view { return strsignal(sig); })
                   .value_or("unknown signal"));
  ASSERT(param.sig_or_code.has_value(), "Expecting a terminating signal to have a signal value");
  return new TraceEvent{param, ::Signal{{param.target}, param.sig_or_code.value()}, TracerEventType::Signal,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::Stepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> bploc,
                    std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event Stepped");
  return new TraceEvent{param, ::Stepped{{param.tid.value()}, stop, bploc, mayresume}, TracerEventType::Stepped,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::SteppingDone(const EventDataParam &param, std::string_view msg, RegisterData &&reg) noexcept
{
  return new TraceEvent{param, ::Stepped{{param.tid.value()}, true, {}, {}, msg}, TracerEventType::Stepped,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::DeferToSupervisor(const EventDataParam &param, RegisterData &&reg, bool attached) noexcept
{
  CORE_EVENT_LOG("creating event DeferToSupervisor");
  return new TraceEvent{param, ::DeferToSupervisor{{param.tid.value()}, attached},
                        TracerEventType::DeferToSupervisor, std::move(reg)};
}

TraceEvent *
TraceEvent::EntryEvent(const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept
{
  CORE_EVENT_LOG("creating event EntryEvent");
  return new TraceEvent{param, ::EntryEvent{{param.tid.value()}, should_stop}, TracerEventType::Entry,
                        std::move(reg)};
}

EventSystem::EventSystem(int wait[2], int commands[2], int debugger[2], int init[2], int internal[2]) noexcept
    : mWaitStatus(wait[0], wait[1]), mCommandEvents(commands[0], commands[1]),
      mDebuggerEvents(debugger[0], debugger[1]), mInitEvents(init[0], init[1]),
      mInternalEvents(internal[0], internal[1])
{
  mPollDescriptors[0] = {mWaitStatus[0], POLLIN, 0};
  mPollDescriptors[1] = {mCommandEvents[0], POLLIN, 0};
  mPollDescriptors[2] = {mDebuggerEvents[0], POLLIN, 0};
  mPollDescriptors[3] = {mInitEvents[0], POLLIN, 0};
  mPollDescriptors[4] = {mInternalEvents[0], POLLIN, 0};
}

/* static */
EventSystem *
EventSystem::Initialize() noexcept
{
  int wait[2];
  int commands[2];
  int dbg[2];
  int init[2];
  int internal[2];

  ASSERT(pipe(wait) != -1, "Failed to open pipe");
  ASSERT(pipe(commands) != -1, "Failed to open pipe");
  ASSERT(pipe(dbg) != -1, "Failed to open pipe");
  ASSERT(pipe(init) != -1, "Failed to open pipe")
  ASSERT(pipe(internal) != -1, "Failed to open pipe")

  for (auto read : {wait[0], commands[0], dbg[0], init[0], internal[0]}) {
    ASSERT(fcntl(read, F_SETFL, O_NONBLOCK) != -1, "failed to set read as non-blocking.");
  }

  EventSystem::sEventSystem = new EventSystem{wait, commands, dbg, init, internal};
  return EventSystem::sEventSystem;
}

void
EventSystem::PushCommand(ui::dap::DebugAdapterClient *debugAdapter, ui::UICommand *cmd) noexcept
{
  std::lock_guard lock(mCommandsGuard);
  cmd->SetDebugAdapterClient(*debugAdapter);
  mCommands.push_back(cmd);
  utils::DebugValue<int> writeValue = write(mCommandEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushDebuggerEvent(TraceEvent *event) noexcept
{
  std::lock_guard lock(mTraceEventGuard);
  mTraceEvents.push_back(event);
  utils::DebugValue<int> writeValue = write(mDebuggerEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::ConsumeDebuggerEvents(std::vector<TraceEvent *> &events) noexcept
{
  std::lock_guard lock(mTraceEventGuard);
  for (auto e : events) {
    mTraceEvents.push_back(e);
  }
  events.clear();
  utils::DebugValue<int> writeValue = write(mDebuggerEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushInitEvent(TraceEvent *event) noexcept
{
  std::lock_guard lock(mTraceEventGuard);
  mInitEvent.push_back(event);
  utils::DebugValue<int> writeValue = write(mInitEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushWaitResult(WaitResult result) noexcept
{
  utils::DebugValue<int> writeValue = write(mWaitStatus[1], &result, sizeof(result));
  ASSERT(writeValue != -1 && writeValue == sizeof(result), "Failed to write notification to pipe");
}

void
EventSystem::PushInternalEvent(InternalEvent event) noexcept
{
  std::lock_guard lock(mInternalEventGuard);
  mInternal.push_back(event);
  utils::DebugValue<int> writeValue = write(mInternalEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

bool
EventSystem::PollBlocking(std::vector<Event> &write) noexcept
{
  int ret = poll(mPollDescriptors, std::size(mPollDescriptors), -1);
  mPollFailures++;
  ASSERT(mPollFailures < 10, "failed to poll event system");
  if (ret == 0) {
    return false;
  }
  mPollFailures = 0;

  auto sizeBefore = write.size();

  // Check for events
  constexpr auto HadEventFilter = [](const pollfd &pfd) { return (pfd.revents & POLLIN) == POLLIN; };
  namespace vw = std::views;

  for (auto &pfd : mPollDescriptors | vw::filter(HadEventFilter)) {
    char buffer[128];
    if (pfd.fd == mCommandEvents[0]) {
      utils::DebugValue<ssize_t> bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mCommandsGuard);
      std::ranges::transform(mCommands, std::back_inserter(write), [](ui::UICommand *cmd) { return Event{cmd}; });
      mCommands.clear();
    } else if (pfd.fd == mDebuggerEvents[0]) {
      utils::DebugValue<ssize_t> bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mTraceEventGuard);
      std::ranges::transform(mTraceEvents, std::back_inserter(write),
                             [](TraceEvent *event) { return Event{event}; });
      mTraceEvents.clear();
    } else if (pfd.fd == mInitEvents[0]) {
      utils::DebugValue<ssize_t> bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mTraceEventGuard);
      std::ranges::transform(mInitEvent, std::back_inserter(write),
                             [](TraceEvent *event) { return Event{event, true}; });
      mInitEvent.clear();
    } else if (pfd.fd == mInternalEvents[0]) {
      utils::DebugValue<ssize_t> bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mInternalEventGuard);
      std::ranges::transform(mInternal, std::back_inserter(write),
                             [](InternalEvent event) { return Event{event}; });
      mInternal.clear();
    } else if (pfd.fd == mWaitStatus[0]) {
      WaitResult result[8];
      constexpr auto bufferSize = sizeof(WaitResult) * std::size(result);
      ssize_t bytesRead = read(pfd.fd, result, bufferSize);
      ASSERT(bytesRead % 8 == 0, "Did not write 8 byte aligned WaitResult value");
      const auto count = bytesRead / sizeof(WaitResult);
      for (auto [pid, stat] : std::span{result, count}) {
        if (WIFSTOPPED(stat)) {
          const auto res = WaitResultToTaskWaitResult(pid, stat);
          write.push_back(Event{WaitEvent{.wait = res, .core = 0}});
        } else if (WIFEXITED(stat)) {
          // We might as well only report this for process-tasks,
          // as DAP doesn't support reporting an exit code for a thread, only for a process,
          // because DAP distinguishes between the two in a way that most OS today, doesn't.
          if (!Tracer::Instance->TraceExitConfigured) {
            // means this is the only place we're getting informed of thread exits
            for (const auto &supervisor : Tracer::Instance->mTracedProcesses) {
              for (const auto &t : supervisor->GetThreads()) {
                if (t->mTid == pid) {
                  write.push_back(Event{
                    TraceEvent::ThreadExited({supervisor->TaskLeaderTid(), pid, WEXITSTATUS(stat)}, false, {})});
                }
              }
            }
          } else {
            for (const auto &supervisor : Tracer::Instance->mTracedProcesses) {
              if (supervisor->TaskLeaderTid() == pid) {
                supervisor->SetExitSeen();
                int exit_code = WEXITSTATUS(stat);
                write.push_back(
                  Event{TraceEvent::ProcessExitEvent(supervisor->TaskLeaderTid(), pid, exit_code, {})});
              }
            }
          }
        } else if (WIFSIGNALED(stat)) {
          const auto signaled_evt = TaskWaitResult{
            .tid = pid, .ws = WaitStatus{.ws = WaitStatusKind::Signalled, .signal = WTERMSIG(stat)}};
          write.push_back(Event{WaitEvent{signaled_evt, 0}});
        } else {
          PANIC("Unknown wait status event");
        }
      }
    }
  }
  return write.size() != sizeBefore;
}

/* static */
EventSystem &
EventSystem::Get() noexcept
{
  return *sEventSystem;
};

// NOLINTEND(cppcoreguidelines-owning-memory)