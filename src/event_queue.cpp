/** LICENSE TEMPLATE */
#include "event_queue.h"

// mdb
#include <common.h>
#include <interface/ui_command.h>
#include <mdbsys/ptrace.h>
#include <tracer.h>
#include <utils/format_utils.h>

// std
#include <mutex>
#include <optional>

// system
#include <fcntl.h>
#include <sys/signalfd.h>

namespace mdb {

int TraceEvent::sMonotonicEventTime = 1;

/* static */
int
TraceEvent::NextEventTime() noexcept
{
  const auto res = sMonotonicEventTime;
  ++sMonotonicEventTime;
  return res;
}

// todo(simon): Major refactor. This file is just a proto-prototype event queue system, to replace the more hacky
// system that was before.

EventSystem *EventSystem::sEventSystem = nullptr;

// NOLINTBEGIN(cppcoreguidelines-owning-memory)

#define INIT_EVENT(EVT, PARAM, REG_DATA) EVT->SetGeneralEventData(PARAM, std::move(REG_DATA));

TraceEvent::TraceEvent(int eventTime) noexcept : mEventTime(eventTime) {}

TraceEvent::TraceEvent() noexcept : TraceEvent(NextEventTime()) {}

constexpr void
TraceEvent::SetGeneralEventData(const EventDataParam &param, RegisterData &&regs) noexcept
{
  mEventTime = param.event_time.value_or(-1);
  mProcessId = param.target;
  mTaskId = param.tid.value();
  uSignal = param.sig_or_code.value_or(0);
  mRegisterData = std::move(regs);
}

void
TraceEvent::InitLibraryEvent(TraceEvent *evt, const EventDataParam &param, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = LibraryEvent{ param.tid.value_or(param.target) };
  evt->mEventType = TracerEventType::LibraryEvent;
}

void
TraceEvent::InitSoftwareBreakpointHit(TraceEvent *evt,
  const EventDataParam &param,
  std::optional<std::uintptr_t> address,
  RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent =
    BreakpointHitEvent{ { param.tid.value_or(-1) }, BreakpointHitEvent::BreakpointType::Software, address };
  evt->mEventType = TracerEventType::BreakpointHitEvent;
}

void
TraceEvent::InitHardwareBreakpointHit(TraceEvent *evt,
  const EventDataParam &param,
  std::optional<std::uintptr_t> address,
  RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent =
    BreakpointHitEvent{ { param.tid.value_or(-1) }, BreakpointHitEvent::BreakpointType::Hardware, address };
  evt->mEventType = TracerEventType::BreakpointHitEvent;
}

void
TraceEvent::InitSyscallEntry(
  TraceEvent *evt, const EventDataParam &param, int syscall, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = SyscallEvent{ { param.tid.value_or(-1) }, SyscallEvent::Boundary::Entry, syscall };
  evt->mEventType = TracerEventType::SyscallEvent;
}

void
TraceEvent::InitSyscallExit(
  TraceEvent *evt, const EventDataParam &param, int syscall, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = SyscallEvent{ { param.tid.value_or(-1) }, SyscallEvent::Boundary::Exit, syscall };
  evt->mEventType = TracerEventType::SyscallEvent;
}

void
TraceEvent::InitThreadCreated(
  TraceEvent *evt, const EventDataParam &param, tc::RunType resumeType, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = ThreadCreated{ { param.tid.value_or(-1) }, resumeType };
  evt->mEventType = TracerEventType::ThreadCreated;
}

void
TraceEvent::InitThreadExited(
  TraceEvent *evt, const EventDataParam &param, bool processNeedsResuming, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = ThreadExited{ { param.tid.value_or(-1) }, param.sig_or_code.value_or(-1), processNeedsResuming };
  evt->mEventType = TracerEventType::ThreadExited;
}

void
TraceEvent::InitWriteWatchpoint(
  TraceEvent *evt, const EventDataParam &param, std::uintptr_t address, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent =
    WatchpointEvent{ { param.tid.value_or(param.target) }, WatchpointEvent::WatchpointType::Write, address };
  evt->mEventType = TracerEventType::WatchpointEvent;
}

void
TraceEvent::InitReadWatchpoint(
  TraceEvent *evt, const EventDataParam &param, std::uintptr_t address, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent =
    WatchpointEvent{ { param.tid.value_or(param.target) }, WatchpointEvent::WatchpointType::Read, address };
  evt->mEventType = TracerEventType::WatchpointEvent;
}

void
TraceEvent::InitAccessWatchpoint(
  TraceEvent *evt, const EventDataParam &param, std::uintptr_t address, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent =
    WatchpointEvent{ { param.tid.value_or(param.target) }, WatchpointEvent::WatchpointType::Access, address };
  evt->mEventType = TracerEventType::WatchpointEvent;
}

void
TraceEvent::InitForkEvent_(
  TraceEvent *evt, const EventDataParam &param, Pid newProcessId, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = ForkEvent{ { param.target }, newProcessId, false };
  evt->mEventType = TracerEventType::Fork;
}

/* static */
void
TraceEvent::InitVForkEvent_(
  TraceEvent *evt, const EventDataParam &param, Pid newProcessId, RegisterData &&regData) noexcept
{
  MDB_ASSERT(param.tid.has_value(), "param must have tid value");
  INIT_EVENT(evt, param, regData)
  evt->mEvent = ForkEvent{ { .mThreadId = param.tid.value() }, newProcessId, true };
  evt->mEventType = TracerEventType::VFork;
}

void
TraceEvent::InitCloneEvent(
  TraceEvent *evt, const EventDataParam &param, Tid newTaskId, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  // TODO: Add support to book keep the stack space of a thread, as well as TLS and thread areas, etc.
  evt->mEvent = Clone{ { param.tid.value() }, newTaskId, nullptr, {}, {} };
  evt->mEventType = TracerEventType::Clone;
}

void
TraceEvent::InitExecEvent(
  TraceEvent *evt, const EventDataParam &param, std::string_view execFile, RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = Exec{ { param.target }, std::string{ execFile } };
  evt->mEventType = TracerEventType::Exec;
}

void
TraceEvent::InitProcessExitEvent(
  TraceEvent *evt, Pid processId, Tid taskId, int exitCode, RegisterData &&regData) noexcept
{
  DBGLOG(core, "[Core Event]: creating event ProcessExitEvent for {}:{}", processId, taskId);
  EventDataParam param{ .target = processId, .tid = taskId, .sig_or_code = exitCode, .event_time = {} };
  INIT_EVENT(evt, param, regData)
  evt->mEvent = ProcessExited{ { taskId }, processId, exitCode };
  evt->mEventType = TracerEventType::ProcessExited;
}

void
TraceEvent::InitSignal(TraceEvent *evt, const EventDataParam &param, RegisterData &&regData) noexcept
{
  MDB_ASSERT(param.sig_or_code.has_value(), "Expecting a terminating signal to have a signal value");
  INIT_EVENT(evt, param, regData)
  evt->mEvent = Signal{ { param.target }, param.sig_or_code.value() };
  evt->mEventType = TracerEventType::Signal;
}

void
TraceEvent::InitStepped(TraceEvent *evt,
  const EventDataParam &param,
  bool stop,
  tc::RunType mayResumeWith,
  RegisterData &&regData) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = Stepped{ { param.tid.value() }, stop, mayResumeWith };
  evt->mEventType = TracerEventType::Stepped;
}

void
TraceEvent::InitDeferToSupervisor(
  TraceEvent *evt, const EventDataParam &param, RegisterData &&regData, bool attached) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = DeferToSupervisor{ { param.tid.value() }, attached };
  evt->mEventType = TracerEventType::DeferToSupervisor;
}

void
TraceEvent::InitEntryEvent(
  TraceEvent *evt, const EventDataParam &param, RegisterData &&regData, bool shouldStop) noexcept
{
  INIT_EVENT(evt, param, regData)
  evt->mEvent = EntryEvent{ { param.tid.value() }, shouldStop };
  evt->mEventType = TracerEventType::Entry;
}

EventSystem::EventSystem(int commands[2], int gdbServer[2], int replay[2], int internal[2]) noexcept
    : mCommandEvents(commands[0], commands[1]), mInternalEvents(internal[0], internal[1]),
      mGdbServerEvents(gdbServer[0], gdbServer[1]), mReplayStopEvents(replay[0], replay[1])
{
  int i = 0;
  mPollDescriptors[i++] = { mCommandEvents[0], POLLIN, 0 };
  mPollDescriptors[i++] = { mGdbServerEvents[0], POLLIN, 0 };
  mPollDescriptors[i++] = { mReplayStopEvents[0], POLLIN, 0 };
  mPollDescriptors[i++] = { mInternalEvents[0], POLLIN, 0 };

  // we set `mCurrentPollDescriptors` to `i`, because to initialize the wait system when we want to
  // we increase `mCurrentPollDescriptors` by 1, and it will be used during the poll in the main event loop.
  mCurrentPolledFdsCount = i;
}

int
EventSystem::PollDescriptorsCount() const noexcept
{
  return mCurrentPolledFdsCount;
}

void
EventSystem::InitWaitStatusManager() noexcept
{
  // Block SIGCHLD in this thread to handle it only via signalfd
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    perror("sigprocmask");
    return;
  }

  mSignalFd = signalfd(-1, &mask, 0);
  VERIFY(
    mSignalFd != -1, "Must be able to open signal file descriptor. StopStatus system can't function otherwise.");
  mPollDescriptors[mCurrentPolledFdsCount++] = { mSignalFd, POLLIN, 0 };
  // Include the signalfd in the polling, essentially "initializing" the wait system as it will now start reporting
  // events
  PushInternalEvent(InitializedWaitSystem{});
}

/* static */
EventSystem *
EventSystem::Initialize() noexcept
{
  int commands[2];
  int gdbServer[2];
  int replay[2];
  int internal[2];

  MUST_HOLD(pipe(commands) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(gdbServer) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(replay) != -1, "Failed to open pipe");
  MUST_HOLD(pipe(internal) != -1, "Failed to open pipe")

  for (auto read : { commands[0], gdbServer[0], replay[0], internal[0] }) {
    MDB_ASSERT(fcntl(read, F_SETFL, O_NONBLOCK) != -1, "failed to set read as non-blocking.");
  }

  EventSystem::sEventSystem = new EventSystem{ commands, gdbServer, replay, internal };
  return EventSystem::sEventSystem;
}

void
EventSystem::PushCommand(ui::dap::DebugAdapterManager *debugAdapter, RefPtr<ui::UICommand> cmd) noexcept
{
  std::lock_guard lock(mCommandsGuard);
  cmd->SetDebugAdapterClient(*debugAdapter);
  DBGLOG(core, "notify of new command... {} for {}", cmd->name(), cmd->mProcessId);
  mCommands.push_back(cmd.Leak());
  int writeValue = write(mCommandEvents[1], "+", 1);
  MDB_ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushReplayStopEvent(ReplayEvent event) noexcept
{
  mLastReplayEvent = event;
  int writeValue = write(mReplayStopEvents[1], "+", 1);
  MDB_ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

void
EventSystem::PushInternalEvent(InternalEvent event) noexcept
{
  std::lock_guard lock(mInternalEventGuard);
  mInternal.push_back(event);
  int writeValue = write(mInternalEvents[1], "+", 1);
  MDB_ASSERT(writeValue != -1, "Failed to write notification to pipe");
}

bool
EventSystem::PollBlocking(std::vector<ApplicationEvent> &write) noexcept
{
  int ret = poll(mPollDescriptors, PollDescriptorsCount(), -1);
  mPollFailures++;
  MDB_ASSERT(mPollFailures < 10, "failed to poll event system");
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
      MDB_ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mCommandsGuard);
      for (auto &&cmd : mCommands) {
        write.emplace_back(ApplicationEvent{ std::move(cmd) });
      }
      mCommands.clear();
    } else if (pfd.fd == mReplayStopEvents[0]) {
      const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
      MDB_ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      write.push_back(ApplicationEvent{ mLastReplayEvent });
    }
    // else if (pfd.fd == mDebuggerEvents[0]) {
    //   const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
    //   MDB_ASSERT(bytesRead != -1, "Failed to flush notification pipe");
    //   std::lock_guard lock(mTraceEventGuard);
    //   std::ranges::transform(
    //     mTraceEvents, std::back_inserter(write), [](TraceEvent *event) { return ApplicationEvent{ event }; });
    //   mTraceEvents.clear();
    // }
    // else if (pfd.fd == mInitEvents[0]) {
    //   const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
    //   MDB_ASSERT(bytesRead != -1, "Failed to flush notification pipe");
    //   std::lock_guard lock(mTraceEventGuard);
    //   std::ranges::transform(
    //     mInitEvent, std::back_inserter(write), [](TraceEvent *event) { return ApplicationEvent{ event, true };
    //     });
    //   mInitEvent.clear();
    // }
    else if (pfd.fd == mInternalEvents[0]) {
      const ssize_t bytesRead = read(pfd.fd, buffer, sizeof(buffer));
      MDB_ASSERT(bytesRead != -1, "Failed to flush notification pipe");
      std::lock_guard lock(mInternalEventGuard);
      std::ranges::transform(
        mInternal, std::back_inserter(write), [](InternalEvent event) { return ApplicationEvent{ event }; });
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
          write.push_back(ApplicationEvent{
            PtraceEvent{ .mPid = status.mProcessId, .mStatus = status.mStatus, .mCpuCore = 0 } });
          // if (WIFSTOPPEReplayEvent *eventD(status.mStatus)) {
          //   const auto res = WaitResultToTaskWaitResult(status.mProcessId, status.mStatus);
          //   write.push_back(ApplicationEvent{ PtraceEvent{ .mWaitResult = res, .mCpuCore = 0 } });
          // } else if (WIFEXITED(status.mStatus)) {
          //   bool handled = false;
          //   for (const auto &supervisor : Tracer::Get().GetAllProcesses()) {
          //     std::vector<Tid> threads{};
          //     if (supervisor->TaskLeaderTid() == status.mProcessId) {
          //       auto *traceEvent = new TraceEvent{};
          //       TraceEvent::InitProcessExitEvent(
          //         traceEvent, status.mProcessId, status.mProcessId, WEXITSTATUS(status.mStatus), {});
          //       write.push_back(ApplicationEvent{ traceEvent });
          //       break;
          //     }
          //     for (const auto &entry : supervisor->GetThreads()) {
          //       threads.push_back(entry.mTid);
          //       if (entry.mTid == status.mProcessId) {
          //         auto *traceEvent = new TraceEvent{};
          //         DBGLOG(core, "Exit code for thread {} exited={}", entry.mTid, WEXITSTATUS(status.mStatus));
          //         TraceEvent::InitThreadExited(traceEvent,
          //           { supervisor->TaskLeaderTid(), status.mProcessId, WEXITSTATUS(status.mStatus), 0 },
          //           false,
          //           {});
          //         write.push_back(ApplicationEvent{ traceEvent });
          //         handled = true;
          //       }
          //     }

          //     if (!handled) {
          //       DBGLOG(core,
          //         "EXIT STATUS went unhandled for {} (threads=[{}]), exit status={}",
          //         status.mProcessId,
          //         JoinFormatIterator{ threads },
          //         WEXITSTATUS(status.mStatus));
          //     }
          //   }

          // } else if (WIFSIGNALED(status.mStatus)) {
          //   const auto signalledEvent = WaitPidResult{ .tid = status.mProcessId,
          //     .ws = StopStatus{ .ws = StopKind::Signalled, .uStopSignal = WTERMSIG(status.mStatus) } };
          //   write.push_back(ApplicationEvent{ PtraceEvent{ signalledEvent, 0 } });
          // } else {
          //   PANIC("Unknown wait status event");
          // }
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