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
TraceEvent::TraceEvent(int eventTime, Pid target, Tid tid, CoreEventVariant &&eventVariant,
                       TracerEventType eventType, int sig_code, RegisterData &&reg) noexcept
    : mProcessId(target), mTaskId(tid), mEvent(std::move(eventVariant)), mEventType(eventType), uSignal(sig_code),
      mRegisterData(std::move(reg))
{
}

TraceEvent::TraceEvent(const EventDataParam &param, CoreEventVariant &&eventVariant, TracerEventType eventType,
                       RegisterData &&regs) noexcept
    : TraceEvent{
        param.event_time.value_or(-1), param.target,   param.tid.value(), std::move(eventVariant), eventType,
        param.sig_or_code.value_or(0), std::move(regs)}
{
}

TraceEvent *
TraceEvent::CreateLibraryEvent(const EventDataParam &param, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event LibraryEvent");
  return new TraceEvent{param, LibraryEvent{param.tid.value_or(param.target)}, TracerEventType::LibraryEvent,
                        std::move(registerData)};
}
TraceEvent *
TraceEvent::CreateSoftwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> address,
                                        RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event SoftwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Software, address},
    TracerEventType::BreakpointHitEvent, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateHardwareBreakpointHit(const EventDataParam &param, std::optional<std::uintptr_t> address,
                                        RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event HardwareBreakpointHit");
  return new TraceEvent{
    param, BreakpointHitEvent{{param.tid.value_or(-1)}, BreakpointHitEvent::BreakpointType::Hardware, address},
    TracerEventType::BreakpointHitEvent, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateSyscallEntry(const EventDataParam &param, int syscall, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event SyscallEntry");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Entry, syscall},
                        TracerEventType::SyscallEvent, std::move(registerData)};
}
TraceEvent *
TraceEvent::CreateSyscallExit(const EventDataParam &param, int syscall, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event SyscallExit");
  return new TraceEvent{param, SyscallEvent{{param.tid.value_or(-1)}, SyscallEvent::Boundary::Exit, syscall},
                        TracerEventType::SyscallEvent, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateThreadCreated(const EventDataParam &param, tc::ResumeAction resumeAction,
                                RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event ThreadCreated");
  return new TraceEvent{param, ThreadCreated{{param.tid.value_or(-1)}, resumeAction},
                        TracerEventType::ThreadCreated, std::move(registerData)};
}
TraceEvent *
TraceEvent::CreateThreadExited(const EventDataParam &param, bool processNeedsResuming,
                               RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event ThreadExited for pid={},tid={}", param.target, param.tid.value_or(-1));
  return new TraceEvent{
    param, ThreadExited{{param.tid.value_or(-1)}, param.sig_or_code.value_or(-1), processNeedsResuming},
    TracerEventType::ThreadExited, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateWriteWatchpoint(const EventDataParam &param, std::uintptr_t address,
                                  RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event WriteWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Write, address},
    TracerEventType::WatchpointEvent, std::move(registerData)};
}
TraceEvent *
TraceEvent::CreateReadWatchpoint(const EventDataParam &param, std::uintptr_t address,
                                 RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event ReadWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Read, address},
    TracerEventType::WatchpointEvent, std::move(registerData)};
}
TraceEvent *
TraceEvent::CreateAccessWatchpoint(const EventDataParam &param, std::uintptr_t address,
                                   RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event AccessWatchpoint");
  return new TraceEvent{
    param, WatchpointEvent{{param.tid.value_or(param.target)}, WatchpointEvent::WatchpointType::Access, address},
    TracerEventType::WatchpointEvent, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateForkEvent_(const EventDataParam &param, Pid newProcessId, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  return new TraceEvent{param, ForkEvent{{param.target}, newProcessId, false}, TracerEventType::Fork,
                        std::move(registerData)};
}

/* static */
TraceEvent *
TraceEvent::CreateVForkEvent_(const EventDataParam &param, Pid newProcessId, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event ForkEvent");
  ASSERT(param.tid.has_value(), "param must have tid value");
  return new TraceEvent{param, ForkEvent{{.mThreadId = param.tid.value()}, newProcessId, true},
                        TracerEventType::VFork, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateCloneEvent(const EventDataParam &param, std::optional<TaskVMInfo> taskStackMetadata,
                             Tid newTaskId, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event CloneEvent, new task: {}", new_tid);
  return new TraceEvent{param, Clone{{param.target}, newTaskId, taskStackMetadata}, TracerEventType::Clone,
                        std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateExecEvent(const EventDataParam &param, std::string_view execFile,
                            RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event ExecEvent");
  return new TraceEvent{param, Exec{{param.target}, std::string{execFile}}, TracerEventType::Exec,
                        std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateProcessExitEvent(Pid processId, Tid taskId, int exitCode, RegisterData &&registerData) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ProcessExitEvent for {}:{}", processId, taskId);
  EventDataParam param{.target = processId, .tid = taskId, .sig_or_code = exitCode, .event_time = {}};
  return new TraceEvent{param, ProcessExited{{taskId}, processId, exitCode}, TracerEventType::ProcessExited,
                        std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateSignal(const EventDataParam &param, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event Signal {}={}", param.sig_or_code.value_or(0),
                 param.sig_or_code.transform([](auto sig) -> std::string_view { return strsignal(sig); })
                   .value_or("unknown signal"));
  ASSERT(param.sig_or_code.has_value(), "Expecting a terminating signal to have a signal value");
  return new TraceEvent{param, Signal{{param.target}, param.sig_or_code.value()}, TracerEventType::Signal,
                        std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateStepped(const EventDataParam &param, bool stop, std::optional<LocationStatus> locationStatus,
                          std::optional<tc::ResumeAction> maybeResumeAction, RegisterData &&registerData) noexcept
{
  CORE_EVENT_LOG("creating event Stepped");
  return new TraceEvent{param, Stepped{{param.tid.value()}, stop, locationStatus, maybeResumeAction},
                        TracerEventType::Stepped, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateSteppingDone(const EventDataParam &param, std::string_view message,
                               RegisterData &&registerData) noexcept
{
  return new TraceEvent{param, Stepped{{param.tid.value()}, true, {}, {}, message}, TracerEventType::Stepped,
                        std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateDeferToSupervisor(const EventDataParam &param, RegisterData &&registerData,
                                    bool attached) noexcept
{
  CORE_EVENT_LOG("creating event DeferToSupervisor");
  return new TraceEvent{param, DeferToSupervisor{{param.tid.value()}, attached},
                        TracerEventType::DeferToSupervisor, std::move(registerData)};
}

TraceEvent *
TraceEvent::CreateEntryEvent(const EventDataParam &param, RegisterData &&registerData, bool shouldStop) noexcept
{
  CORE_EVENT_LOG("creating event EntryEvent");
  return new TraceEvent{param, EntryEvent{{param.tid.value()}, shouldStop}, TracerEventType::Entry,
                        std::move(registerData)};
}

EventSystem::EventSystem(int commands[2], int debugger[2], int init[2], int internal[2]) noexcept
    : mCommandEvents(commands[0], commands[1]), mDebuggerEvents(debugger[0], debugger[1]),
      mInitEvents(init[0], init[1]), mInternalEvents(internal[0], internal[1])
{
  int i = 0;
  mPollDescriptors[i++] = {mCommandEvents[0], POLLIN, 0};
  mPollDescriptors[i++] = {mDebuggerEvents[0], POLLIN, 0};
  mPollDescriptors[i++] = {mInitEvents[0], POLLIN, 0};
  mPollDescriptors[i++] = {mInternalEvents[0], POLLIN, 0};

  // Block SIGCHLD in this thread to handle it only via signalfd
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    perror("sigprocmask");
    return;
  }
  // we set `mCurrentPollDescriptors` to `i`, because to initialize the wait system when we want to
  // we increase `mCurrentPollDescriptors` by 1, and it will be used during the poll in the main event loop.
  mCurrentPollDescriptors = i;
  mSignalFd = signalfd(-1, &mask, 0);
  VERIFY(mSignalFd != -1,
         "Must be able to open signal file descriptor. WaitStatus system can't function otherwise.");
  mPollDescriptors[i++] = {mSignalFd, POLLIN, 0};
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
  int commands[2];
  int dbg[2];
  int init[2];
  int internal[2];

  MUST_HOLD(pipe(commands) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(dbg) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(init) != -1, "Failed to open pipe")
  MUST_HOLD(pipe(internal) != -1, "Failed to open pipe")

  for (auto read : {commands[0], dbg[0], init[0], internal[0]}) {
    ASSERT(fcntl(read, F_SETFL, O_NONBLOCK) != -1, "failed to set read as non-blocking.");
  }

  EventSystem::sEventSystem = new EventSystem{commands, dbg, init, internal};
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
      const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mCommandsGuard);
      std::ranges::transform(mCommands, std::back_inserter(write), [](ui::UICommand *cmd) { return Event{cmd}; });
      mCommands.clear();
    } else if (pfd.fd == mDebuggerEvents[0]) {
      const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mTraceEventGuard);
      std::ranges::transform(mTraceEvents, std::back_inserter(write),
                             [](TraceEvent *event) { return Event{event}; });
      mTraceEvents.clear();
    } else if (pfd.fd == mInitEvents[0]) {
      const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mTraceEventGuard);
      std::ranges::transform(mInitEvent, std::back_inserter(write),
                             [](TraceEvent *event) { return Event{event, true}; });
      mInitEvent.clear();
    } else if (pfd.fd == mInternalEvents[0]) {
      const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
      ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mInternalEventGuard);
      std::ranges::transform(mInternal, std::back_inserter(write),
                             [](InternalEvent event) { return Event{event}; });
      mInternal.clear();
    } else if (pfd.fd == mSignalFd) {
      signalfd_siginfo signalInfoFd;
      const ssize_t bytesRead = read(mSignalFd, &signalInfoFd, sizeof(signalInfoFd));
      if (bytesRead != sizeof(signalInfoFd)) {
        PANIC("read from signalfd");
      }
      if (signalInfoFd.ssi_signo == SIGCHLD) {
        // Handle SIGCHLD: reap child processes
        while (true) {
          WaitResult status{};
          status.mProcessId = waitpid(-1, &status.mStatus, WNOHANG | __WALL);
          if (status.mProcessId <= 0) {
            break;
          }
          if (WIFSTOPPED(status.mStatus)) {
            const auto res = WaitResultToTaskWaitResult(status.mProcessId, status.mStatus);
            write.push_back(Event{WaitEvent{.mWaitResult = res, .mCpuCore = 0}});
          } else if (WIFEXITED(status.mStatus)) {
            for (const auto &supervisor : Tracer::Get().GetAllProcesses()) {
              for (const auto &entry : supervisor->GetThreads()) {
                if (entry.mTid == status.mProcessId) {
                  write.push_back(Event{TraceEvent::CreateThreadExited(
                    {supervisor->TaskLeaderTid(), status.mProcessId, WEXITSTATUS(status.mStatus), 0}, false, {})});
                }
              }
            }

          } else if (WIFSIGNALED(status.mStatus)) {
            const auto signalledEvent = TaskWaitResult{
              .tid = status.mProcessId,
              .ws = WaitStatus{.ws = WaitStatusKind::Signalled, .signal = WTERMSIG(status.mStatus)}};
            write.push_back(Event{WaitEvent{signalledEvent, 0}});
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