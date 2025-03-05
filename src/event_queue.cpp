/** LICENSE TEMPLATE */
#include "event_queue.h"
#include "common.h"
#include "supervisor.h"
#include "tracer.h"
#include <cstring>
#include <fcntl.h>
#include <interface/ui_command.h>
#include <mutex>
#include <optional>
#include <sys/signalfd.h>

namespace mdb {

// todo(simon): Major refactor. This file is just a proto-prototype event queue system, to replace the more hacky
// system that was before.

EventSystem *EventSystem::sEventSystem = nullptr;

#define CORE_EVENT_LOG(fmtstring, ...)
// DBGLOG(core, "[{} event {}:{}]: " fmtstring, __FUNCTION__, param.target,
//  param.tid.value_or(-1) __VA_OPT__(, ) __VA_ARGS__)

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
TraceEvent::TraceEvent(int event_time, Pid target, Tid tid, CoreEventVariant &&p, TracerEventType type,
                       int sig_code, RegisterData &&reg) noexcept
    : target(target), tid(tid), event(std::move(p)), event_type(type), signal(sig_code), registers(std::move(reg))
{
}

TraceEvent::TraceEvent(const EventDataParam &param, CoreEventVariant &&p, TracerEventType type,
                       RegisterData &&regs) noexcept
    : TraceEvent{param.event_time.value_or(-1), param.target,   param.tid.value(), std::move(p), type,
                 param.sig_or_code.value_or(0), std::move(regs)}
{
}

TraceEvent *
TraceEvent::CreateLibraryEvent(const EventDataParam &param, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event LibraryEvent");
  return new TraceEvent{param, LibraryEvent{param.tid.value_or(param.target)}, TracerEventType::LibraryEvent,
                        std::move(reg)};
}
TraceEvent *
TraceEvent::CreateSoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                        RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SoftwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Software, addr},
    TracerEventType::BreakpointHitEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateHardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> addr,
                                        RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event HardwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Hardware, addr},
    TracerEventType::BreakpointHitEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateSyscallEntry(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SyscallEntry");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Entry, syscall},
                        TracerEventType::SyscallEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::CreateSyscallExit(const EventDataParam &param, int syscall, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event SyscallExit");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Exit, syscall},
                        TracerEventType::SyscallEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateThreadCreated(const EventDataParam &param, tc::ResumeAction resume_action,
                                RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ThreadCreated");
  return new TraceEvent{param, ThreadCreated{{param.tid.value_or(-1)}, resume_action},
                        TracerEventType::ThreadCreated, std::move(reg)};
}
TraceEvent *
TraceEvent::CreateThreadExited(const EventDataParam &param, bool process_needs_resuming,
                               RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ThreadExited for pid={},tid={}", param.target, param.tid.value_or(-1));
  return new TraceEvent{
    param, ThreadExited{{param.tid.value_or(-1)}, param.sig_or_code.value_or(-1), process_needs_resuming},
    TracerEventType::ThreadExited, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateWriteWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event WriteWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Write, addr},
    TracerEventType::WatchpointEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::CreateReadWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ReadWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Read, addr},
    TracerEventType::WatchpointEvent, std::move(reg)};
}
TraceEvent *
TraceEvent::CreateAccessWatchpoint(const EventDataParam &param, std::uintptr_t addr, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event AccessWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Access, addr},
    TracerEventType::WatchpointEvent, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  return new TraceEvent{param, ForkEvent{{param.target}, new_pid, false}, TracerEventType::Fork, std::move(reg)};
}

/* static */
TraceEvent *
TraceEvent::CreateVForkEvent_(const EventDataParam &param, Pid new_pid, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  ASSERT(param.tid.has_value(), "param must have tid value");
  return new TraceEvent{param, ForkEvent{{.thread_id = param.tid.value()}, new_pid, true}, TracerEventType::VFork,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CreateCloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> vm_info, Tid new_tid,
                             RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event CloneEvent, new task: {}", new_tid);
  return new TraceEvent{param, Clone{{param.target}, new_tid, vm_info}, TracerEventType::Clone, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateExecEvent(const EventDataParam &param, std::string_view exec_file, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event ExecEvent");
  return new TraceEvent{param, Exec{{param.target}, std::string{exec_file}}, TracerEventType::Exec,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CreateProcessExitEvent(Pid pid, Tid tid, int exit_code, RegisterData &&reg) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ProcessExitEvent for {}:{}", pid, tid);
  EventDataParam param{.target = pid, .tid = tid, .sig_or_code = exit_code, .event_time = {}};
  return new TraceEvent{param, ProcessExited{{tid}, pid, exit_code}, TracerEventType::ProcessExited,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CreateSignal(const EventDataParam &param, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event Signal {}={}", param.sig_or_code.value_or(0),
                 param.sig_or_code.transform([](auto sig) -> std::string_view { return strsignal(sig); })
                   .value_or("unknown signal"));
  ASSERT(param.sig_or_code.has_value(), "Expecting a terminating signal to have a signal value");
  return new TraceEvent{param, Signal{{param.target}, param.sig_or_code.value()}, TracerEventType::Signal,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CreateStepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> bploc,
                          std::optional<tc::ResumeAction> mayresume, RegisterData &&reg) noexcept
{
  CORE_EVENT_LOG("creating event Stepped");
  return new TraceEvent{param, Stepped{{param.tid.value()}, stop, bploc, mayresume}, TracerEventType::Stepped,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CreateSteppingDone(const EventDataParam &param, std::string_view msg, RegisterData &&reg) noexcept
{
  return new TraceEvent{param, Stepped{{param.tid.value()}, true, {}, {}, msg}, TracerEventType::Stepped,
                        std::move(reg)};
}

TraceEvent *
TraceEvent::CreateDeferToSupervisor(const EventDataParam &param, RegisterData &&reg, bool attached) noexcept
{
  CORE_EVENT_LOG("creating event DeferToSupervisor");
  return new TraceEvent{param, DeferToSupervisor{{param.tid.value()}, attached},
                        TracerEventType::DeferToSupervisor, std::move(reg)};
}

TraceEvent *
TraceEvent::CreateEntryEvent(const EventDataParam &param, RegisterData &&reg, bool should_stop) noexcept
{
  CORE_EVENT_LOG("creating event EntryEvent");
  return new TraceEvent{param, EntryEvent{{param.tid.value()}, should_stop}, TracerEventType::Entry,
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

  // Block SIGCHLD in this thread to handle it only via signalfd
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    perror("sigprocmask");
    return;
  }

  // Create signalfd for SIGCHLD

  // ScopedFd panics if fd == -1 (error value).
  // So we don't need error checking here. This is a hard error, we don't even try here.
  mSignalFd = signalfd(-1, &mask, 0);
  VERIFY(mSignalFd != -1,
         "Must be able to open signal file descriptor. WaitStatus system can't function otherwise.");
  mPollDescriptors[5] = {mSignalFd, POLLIN, 0};
}

int
EventSystem::PollDescriptorsCount() const noexcept
{
  return mCurrentPollDescriptors;
}

void
EventSystem::InitWaitStatusManager() noexcept
{
  // Include the signalfd in the polling, essentially "initializing" the wait system as it will now start reporting
  // events
  mCurrentPollDescriptors++;
  PushInternalEvent(InitializedWaitSystem{});
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

  MUST_HOLD(pipe(wait) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(commands) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(dbg) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(init) != -1, "Failed to open pipe")
  MUST_HOLD(pipe(internal) != -1, "Failed to open pipe")

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
  DBGLOG(core, "notify of new command...");
  int writeValue = write(mCommandEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushDebuggerEvent(TraceEvent *event) noexcept
{
  std::lock_guard lock(mTraceEventGuard);
  mTraceEvents.push_back(event);
  int writeValue = write(mDebuggerEvents[1], "+", 1);
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
  int writeValue = write(mDebuggerEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushInitEvent(TraceEvent *event) noexcept
{
  std::lock_guard lock(mTraceEventGuard);
  mInitEvent.push_back(event);
  int writeValue = write(mInitEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushWaitResult(WaitResult result) noexcept
{
  int writeValue = write(mWaitStatus[1], &result, sizeof(result));
  ASSERT(writeValue != -1 && writeValue == sizeof(result), "Failed to write notification to pipe");
}

void
EventSystem::NotifyNewWaitpidResults() noexcept
{
  constexpr char writeChar = '+';
  int writeValue = write(mWaitStatus[1], &writeChar, sizeof(writeChar));
  ASSERT(writeValue != -1 && writeValue == sizeof(writeChar), "Failed to write notification to pipe");
}

void
EventSystem::PushReapedWaitResults(std::span<WaitResult> results) noexcept
{
  std::lock_guard lock(mInternalEventGuard);
  for (const auto [pid, stat] : results) {
    if (WIFSTOPPED(stat)) {
      const auto res = WaitResultToTaskWaitResult(pid, stat);
      mWaitEvents.push_back(Event{WaitEvent{.wait = res, .core = 0}});
    } else if (WIFEXITED(stat)) {
      for (const auto &supervisor : Tracer::Get().GetAllProcesses()) {
        for (const auto &entry : supervisor->GetThreads()) {
          if (entry.mTid == pid) {
            mWaitEvents.push_back(Event{TraceEvent::CreateThreadExited(
              {supervisor->TaskLeaderTid(), pid, WEXITSTATUS(stat), 0}, false, {})});
          }
        }
      }

    } else if (WIFSIGNALED(stat)) {
      const auto signaled_evt =
        TaskWaitResult{.tid = pid, .ws = WaitStatus{.ws = WaitStatusKind::Signalled, .signal = WTERMSIG(stat)}};
      mWaitEvents.push_back(Event{WaitEvent{signaled_evt, 0}});
    } else {
      PANIC("Unknown wait status event");
    }
  }
  NotifyNewWaitpidResults();
}

void
EventSystem::PushInternalEvent(InternalEvent event) noexcept
{
  std::lock_guard lock(mInternalEventGuard);
  mInternal.push_back(event);
  int writeValue = write(mInternalEvents[1], "+", 1);
  ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

bool
EventSystem::PollBlocking(std::vector<Event> &write) noexcept
{
  int ret = poll(mPollDescriptors, PollDescriptorsCount(), -1);
  mPollFailures++;
  ASSERT(mPollFailures < 10, "failed to poll event system");
  if (ret == 0) {
    return false;
  }
  mPollFailures = 0;

  auto sizeBefore = write.size();

  // Check for events
  for (auto &pfd : mPollDescriptors) {
    if ((pfd.revents & POLLIN) != POLLIN) {
      continue;
    }
    char buffer[128];
    if (pfd.fd == mCommandEvents[0]) {
      ssize_t bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mCommandsGuard);
      std::ranges::transform(mCommands, std::back_inserter(write), [](ui::UICommand *cmd) { return Event{cmd}; });
      mCommands.clear();
    } else if (pfd.fd == mDebuggerEvents[0]) {
      ssize_t bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mTraceEventGuard);
      std::ranges::transform(mTraceEvents, std::back_inserter(write),
                             [](TraceEvent *event) { return Event{event}; });
      mTraceEvents.clear();
    } else if (pfd.fd == mInitEvents[0]) {
      ssize_t bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mTraceEventGuard);
      std::ranges::transform(mInitEvent, std::back_inserter(write),
                             [](TraceEvent *event) { return Event{event, true}; });
      mInitEvent.clear();
    } else if (pfd.fd == mInternalEvents[0]) {
      ssize_t bytes_read = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytes_read != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mInternalEventGuard);
      std::ranges::transform(mInternal, std::back_inserter(write),
                             [](InternalEvent event) { return Event{event}; });
      mInternal.clear();
    } else if (pfd.fd == mWaitStatus[0]) {
      std::lock_guard lock(mInternalEventGuard);
      write.reserve(write.size() + mWaitEvents.size());
      std::copy(mWaitEvents.begin(), mWaitEvents.end(), std::back_inserter(write));
      mWaitEvents.clear();
    } else if (pfd.fd == mSignalFd) {
      signalfd_siginfo fdsi;
      ssize_t bytes_read = read(mSignalFd, &fdsi, sizeof(fdsi));
      if (bytes_read != sizeof(fdsi)) {
        PANIC("read from signalfd");
      }
      if (fdsi.ssi_signo == SIGCHLD) {
        // Handle SIGCHLD: reap child processes
        while (true) {
          WaitResult status{};
          status.pid = waitpid(-1, &status.stat, WNOHANG | __WALL);
          if (status.pid <= 0) {
            break;
          }
          if (WIFSTOPPED(status.stat)) {
            const auto res = WaitResultToTaskWaitResult(status.pid, status.stat);
            write.push_back(Event{WaitEvent{.wait = res, .core = 0}});
          } else if (WIFEXITED(status.stat)) {
            for (const auto &supervisor : Tracer::Get().GetAllProcesses()) {
              for (const auto &entry : supervisor->GetThreads()) {
                if (entry.mTid == status.pid) {
                  write.push_back(Event{TraceEvent::CreateThreadExited(
                    {supervisor->TaskLeaderTid(), status.pid, WEXITSTATUS(status.stat), 0}, false, {})});
                }
              }
            }

          } else if (WIFSIGNALED(status.stat)) {
            const auto signaled_evt =
              TaskWaitResult{.tid = status.pid,
                             .ws = WaitStatus{.ws = WaitStatusKind::Signalled, .signal = WTERMSIG(status.stat)}};
            write.push_back(Event{WaitEvent{signaled_evt, 0}});
          } else {
            PANIC("Unknown wait status event");
          }
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
} // namespace mdb
// NOLINTEND(cppcoreguidelines-owning-memory)