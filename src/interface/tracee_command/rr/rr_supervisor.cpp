/** LICENSE TEMPLATE */
#include "rr_supervisor.h"
#include "TraceFrame.h"
#include "interface/dap/events.h"

// mdb
#include <common/macros.h>
#include <common/traits.h>
#include <cstring>
#include <event_queue.h>
#include <interface/tracee_command/rr/rr_session.h>
#include <mdbsys/stop_status.h>
#include <sys/user.h>
#include <task.h>
#include <utils/format_utils.h>
#include <utils/logger.h>

// std
#include <algorithm>
#include <filesystem>
#include <utility>
// system

// rr
#include <Flags.h>
#include <ReplayTimeline.h>
#include <Session.h>
#include <kernel_abi.h>

namespace fs = std::filesystem;

#define RRLOG(FORMAT_STRING, ...)                                                                                 \
  DBGBUFLOG(core,                                                                                                 \
    "[replay@{}]: " FORMAT_STRING,                                                                                \
    mTimeline->current_session().current_frame_time() __VA_OPT__(, ) __VA_ARGS__);

namespace mdb {
/* static */
TraceFrameTaskContext
TraceFrameTaskContext::From(int signal, const rr::ReplayTask &task, pid_t newChild) noexcept
{
  return TraceFrameTaskContext{ .mRIP = task.regs().ip().register_value(),
    .mFrameTime = task.current_frame_time(),
    .mTaskTickCount = task.tick_count(),
    .mSignal = signal,
    .mRecTid = task.rec_tid,
    .mTaskLeader = task.thread_group()->tgid,
    .mNewTaskIfAny = newChild,
    .mIsValid = true };
}
} // namespace mdb

namespace mdb::tc::replay {

static SupervisorEvent
SupervisorEventFromTask(SupervisorSessionEventType kind, const rr::ReplayTask *t)
{
  if (t) {
    return SupervisorEvent{ SessionEvent{ .mType = kind, .mTaskInfo = TraceFrameTaskContext::From(0, *t) } };
  } else {
    return SupervisorEvent{ SessionEvent{ .mType = kind, .mTaskInfo = { .mIsValid = false } } };
  }
}

void
ReplaySupervisor::StartReplay(const char *traceDir, std::function<void()> onStartCompleted) noexcept
{
  mTraceDir = traceDir;
  mIssuedStartRequest = true;
  mHasReplayCondVar.notify_one();
  mSupervisorEvents.emplace(SupervisorSessionEventType::TraceStarted, std::move(onStartCompleted));
}

std::vector<Pid>
ReplaySupervisor::CurrentLiveProcesses() const noexcept
{
  std::vector<Pid> res;
  for (const auto &[k, b] : mTimeline->current_session().thread_group_map()) {
    const auto proc = b->tguid().tid();
    res.push_back(proc);
  }
  return res;
}

Session *
ReplaySupervisor::CachedSupervisor(Tid taskLeader) const noexcept
{
  for (auto s : mTimelineSupervisors) {
    if (s->TaskLeaderTid() == taskLeader) {
      return s;
    }
  }

  return nullptr;
}

void
ReplaySupervisor::AddSupervisor(NonNullPtr<Session> session) noexcept
{
  mTimelineSupervisors.push_back(session);
}

void
ReplaySupervisor::RegisterStopsForProcess(Pid pid) noexcept
{
  MDB_ASSERT(!IsTracing(pid), "Already added {}", pid);
  mTracedProcesses.push_back(pid);
}

bool
ReplaySupervisor::IsTracing(Pid pid) noexcept
{
  return std::ranges::any_of(mTracedProcesses, [pid](auto p) { return p == pid; });
}

bool
ReplaySupervisor::IsIgnoring(Pid pid) noexcept
{
  for (const auto &processId : mInitOptions.mIgnoredProcesses) {
    if (processId == pid) {
      return true;
    }
  }
  return false;
}

void
ReplaySupervisor::WaitForEvent() noexcept
{
  std::unique_lock lock(mRequestMutex);
  mRequestCondVar.wait(lock, [&]() { return mHasRequest; });
  mHasRequest = false;
}

void
ReplaySupervisor::ProcessRequests()
{
  if (mRequestedResume) {
    MDB_ASSERT(mReplayRunning == false, "Expected replay to not be running");
    mReplayRunning = true;

    while (true && !InterruptCheck()) {
      const auto replayResult = PerformResume();
      auto replayedTask = replayResult.break_status.task();

      auto t = mTimeline->current_session().current_task();
      RRLOG("replayed one step, replayed_task = {}, current_task={}, exited={}, fastfwd={}, res={}, pc=0x{:x}",
        replayedTask ? replayedTask->rec_tid : 0,
        t ? t->rec_tid : 0,
        replayResult.break_status.task_exit,
        replayResult.did_fast_forward,
        (int)replayResult.status,
        t ? t->ip().register_value() : 0);

      if (replayResult.status == rr::REPLAY_EXITED) {
        RRLOG("replay exited");
        PublishSessionEvent(SupervisorSessionEventType::TraceEnded);
        return;
      }

      if (!replayedTask) {
        continue;
      }

      if (const auto res = FromReplayResult(replayResult, *mRequestedResume);
        res && !IsIgnoring(t->thread_group()->tgid)) {
        PublishEvent(*res);
        InterruptCheck();
        SetWillNeedResume(&replayResult.break_status);
        break;
      }
      if (mRequestedResume->resume_type == ResumeType::RR_STEP && mRequestedResume->steps > 0) {
        --mRequestedResume->steps;
      }
    }
  } else if (mRequestedShutdown) {
    RRLOG("Destroying timeline");
    delete mTimeline;
    mTimeline = nullptr;
    mKeepRunning = false;
    PublishSessionEvent(SupervisorSessionEventType::TraceEnded);
  }
}

bool
ReplaySupervisor::HasSession() const
{
  return mKeepRunning && mTimeline != nullptr;
}

bool
ReplaySupervisor::IsReplaying() const
{
  return mReplayRunning;
}

void
ReplaySupervisor::SetEventHandler(SupervisorEventCallback eventHandler) noexcept
{
  mEventCallback = EventCallback{ eventHandler, this };
}

bool
RRInit()
{
  int key;
  rr::good_random(&key, sizeof(key));
  srandom(key);
  srand(key);

  rr::raise_resource_limits();

  return true;
}

void
ReplaySupervisor::InitLibrary()
{
  if (!RRInit()) {
    PublishSessionEvent(SupervisorSessionEventType::Exited);
    return;
  }
  PublishSessionEvent(SupervisorSessionEventType::Initialized);
}

void
ReplaySupervisor::Shutdown()
{
  // This requests needs queuing, because shut down needs to happen on the same
  // thread that initialized the supervisor.
  mRequestedShutdown = true;
  mRequestedResume.reset();
}

bool
ReplaySupervisor::RequestResume(ResumeReplay resume_tracee)
{
  RRLOG("requesting resume");
  if (IsReplaying()) {
    RRLOG("supervisor is running - resume request discarded!");
    return false;
  }

  mRequestedResume = resume_tracee;

  NotifyResumed();
  return true;
}

pid_t
ReplaySupervisor::GetTaskToResume() const
{
  if (auto task = mTimeline->current_session().current_task()) {
    return task->rec_tid;
  }
  return 0;
}

bool
ReplaySupervisor::RequestInterrupt(pid_t rec_tid)
{
  if (!IsReplaying()) {
    return true;
  }
  mPendingInterrupt = true;
  mLastPendingInterruptFor = rec_tid;
  return false;
}

#define MUTEX_RUNNING(ERR_RESULT)                                                                                 \
  if (IsReplaying()) {                                                                                            \
    return ERR_RESULT;                                                                                            \
  }

int64_t
ReplaySupervisor::ReadMemory(pid_t recTid, uintptr_t address, int bufferSize, void *buf)
{
  MUTEX_RUNNING(-1);
  DBGBUFLOG(core, "Read from target {} at 0x{:x}, {} bytes", recTid, address, bufferSize);

  rr::ReplayTask *t = mTimeline->current_session().find_task(recTid);
  MDB_ASSERT(t != nullptr, "Expected to find task {}", recTid);
  if (!t) {
    return -1;
  }
  auto read = t->read_bytes_fallible(address, bufferSize, buf);
  return read;
}

RegisterCacheData
ReplaySupervisor::ReadRegisters(pid_t recTid)
{
  auto task = mTimeline->current_session().find_task(recTid);
  if (!task) {
    std::vector<pid_t> threads;
    threads.reserve(mTimeline->current_session().tasks().size());
    for (const auto &t : mTimeline->current_session().tasks()) {
      threads.push_back(t.second->rec_tid);
    }
    RRLOG("Could not read registers, task {} not found, tasks={}", recTid, JoinFormatIterator{ threads });
    return RegisterCacheData{ nullptr, 0 };
  }

  const auto &regs = task->regs();
  auto internal_data = regs.get_ptrace_for_self_arch();
  return RegisterCacheData{ .buf = internal_data.data, .cache_size = internal_data.size };
}

bool
ReplaySupervisor::SetBreakpoint(pid_t rec_tid, BreakpointRequest req)
{
  RRLOG(
    "setting {} breakpoint task={}, addr=0x{:x}", req.is_hardware ? "hardware" : "software", rec_tid, req.address);
  MUTEX_RUNNING(false);

  auto task = mTimeline->current_session().find_task(rec_tid);
  if (req.is_hardware) {
    return mTimeline->add_watchpoint(task, rr::remote_ptr<void>{ req.address }, 1, rr::WatchType::WATCH_EXEC);
  } else {
    return mTimeline->add_breakpoint(task, rr::remote_code_ptr{ req.address });
  }
}

bool
ReplaySupervisor::SetWatchpoint(pid_t recTid, WatchpointRequest req)
{
  rr::WatchType type = rr::WATCH_READWRITE;
  using enum WatchpointRequestType;
  switch (req.type) {
  case WATCHPOINT_EXEC:
    type = rr::WATCH_EXEC;
    break;
  case WATCHPOINT_WRITE:
    type = rr::WATCH_WRITE;
    break;
  case WATCHPOINT_RW:
    type = rr::WATCH_READWRITE;
    break;
  default:
    PANIC("Invalid type");
  }

  MUTEX_RUNNING(false);
  auto task = mTimeline->current_session().find_task(recTid);
  mTimeline->add_watchpoint(task, rr::remote_ptr<void>{ req.address }, req.size, type);
  return true;
}

bool
ReplaySupervisor::RemoveBreakpoint(pid_t rec_tid, BreakpointRequest req)
{
  RRLOG("removing {} for {}", req.is_hardware ? "watchpoint" : "breakpoint", rec_tid);
  MUTEX_RUNNING(false);
  auto task = mTimeline->current_session().find_task(rec_tid);
  if (req.is_hardware) {
    mTimeline->remove_watchpoint(task, rr::remote_ptr<void>{ req.address }, 1, rr::WatchType::WATCH_EXEC);
  } else {
    mTimeline->remove_breakpoint(task, rr::remote_code_ptr{ req.address });
  }
  return true;
}

bool
ReplaySupervisor::RemoveWatchpoint(pid_t rec_tid, WatchpointRequest req)
{
  MUTEX_RUNNING(false);
  auto task = mTimeline->current_session().find_task(rec_tid);
  rr::WatchType t{};
  using enum WatchpointRequestType;
  switch (req.type) {
  case WATCHPOINT_EXEC:
    t = rr::WATCH_EXEC;
    break;
  case WATCHPOINT_WRITE:
    t = rr::WATCH_WRITE;
    break;
  case WATCHPOINT_RW:
    t = rr::WATCH_READWRITE;
    break;
  }

  mTimeline->remove_watchpoint(task, rr::remote_ptr<void>(req.address), req.size, t);
  return true;
}

const char *
ReplaySupervisor::ExecedFile(pid_t recTid) const
{
  MUTEX_RUNNING(nullptr);
  rr::ReplayTask *task = GetTask(recTid);
  return task->vm()->exe_image().c_str();
}

const std::vector<std::uint8_t> &
ReplaySupervisor::GetAuxv(pid_t rec_tid)
{
  auto *task = GetTask(rec_tid);
  return task->vm()->saved_auxv();
}

rr::ReplayTask *
ReplaySupervisor::GetTask(pid_t rec_tid) const
{
  return mTimeline->current_session().find_task(rec_tid);
}

static rr::ReplaySession::Flags
CreateReplayFlags(const StartReplayOptions &options)
{
  // For now, configure these to be default of gdbserver's
  rr::ReplaySession::Flags result;
  result.redirect_stdio = true;
  result.redirect_stdio_file = {};
  result.share_private_mappings = false;
  result.cpu_unbound = false;
  result.intel_pt_start_checking_event = -1;
  result.transient_errors_fatal = true;
  return result;
}

static bool
IsAtLastThreadExit(const rr::BreakStatus &break_status)
{
  return break_status.task_exit && break_status.task_context.thread_group->task_set().size() <= 1;
}

// N.B. - Refactored from GdbServer.cc with the same name
static bool
TargetEventReached(
  const rr::ReplayTimeline &timeline, const StartReplayOptions &options, const rr::ReplayResult &result)
{
  if (options.goto_event == -1) {
    return IsAtLastThreadExit(result.break_status);
  } else {
    return timeline.current_session().current_trace_frame().time() > options.goto_event;
  }
}

// N.B. - Refactored from GdbServer.cc with the same name
static bool
AtTarget(rr::ReplayTimeline &timeline,
  const StartReplayOptions &options,
  std::atomic<bool> &stop_flag,
  const rr::ReplayResult &result)
{
  if (!timeline.current_session().done_initial_exec()) {
    return false;
  }
  rr::Task *t = timeline.current_session().current_task();
  if (!t) {
    return false;
  }

  bool target_is_exit = options.goto_event == -1;
  if (!(timeline.can_add_checkpoint() || target_is_exit)) {
    return false;
  }
  // We don't need synchronization with other operations, this is simply a flag.
  // if it's true it is true if not, its not, so to speak
  if (stop_flag.load(std::memory_order_relaxed)) {
    return true;
  }

  return TargetEventReached(timeline, options, result) && t->execed() &&
         // Ensure we're at the start of processing an event. We don't
         // want to attach while we're finishing an exec() since that's a
         // slightly confusing state for ReplayTimeline's reverse execution.
         (!timeline.current_session().current_step_key().in_execution() || target_is_exit);
}

void
ReplaySupervisor::PublishEvent(const SupervisorEvent &evt) noexcept
{
  mEventCallback(evt);
}

void
ReplaySupervisor::PublishSessionEvent(
  SupervisorSessionEventType type, const TraceFrameTaskContext &taskContext) noexcept
{
  DBGLOG(core, "publish session event {}", type);
  PublishEvent(SessionEvent{ type, taskContext });
}

void
ReplaySupervisor::InitializeDebugSession()
{
  const auto &opts = mReplayOptions.value();
  const auto flags = CreateReplayFlags(opts);
  mTimeline = new rr::ReplayTimeline{ rr::ReplaySession::create(opts.trace_dir, flags) };
  MDB_ASSERT(mTimeline != nullptr, "Failed to create replay session");
  if (!mTimeline) {
    std::terminate();
  }

  rr::ReplayResult result;
  bool isAtTarget = false;
  do {
    RRLOG("perform replay step forward");
    result = mTimeline->replay_step_forward(rr::RUN_CONTINUE);
    if (result.status == rr::REPLAY_EXITED) {
      RRLOG("Debugger was not launched before end of trace.");
      return;
    }
    RRLOG("check if at target");
    isAtTarget = AtTarget(*mTimeline, opts, mPendingInterrupt, result);
    RRLOG("not at target, yet");
  } while (!isAtTarget);
  RRLOG("Reached replay target");

  // Turn off pending interrupt now, if it was set because from now on, a
  // pending interrupt actually means notifying a user of something too (e.g.
  // "paused", "interrupted reverse continue" etc)
  mPendingInterrupt = false;

  rr::ReplayTask *t = mTimeline->current_session().current_task();

  const rr::FrameTime firstRunEvent = std::max(t->vm()->first_run_event(), t->thread_group()->first_run_event());
  if (firstRunEvent) {
    mTimeline->set_reverse_execution_barrier_event(firstRunEvent);
  }

  RRLOG("publish 'started' event");

  PublishSessionEvent(SupervisorSessionEventType::TraceStarted, TraceFrameTaskContext::From(0, *t));
}

void
ReplaySupervisor::SetWillNeedResume(const rr::BreakStatus *breakStatus)
{
  RRLOG("supervisor stopped, will need explicit resume from user");
  mReplayRunning = false;
  mRequestedResume.reset();

  if (breakStatus && breakStatus->any_break()) {
    if (!mSavedBreakStatus) {
      mSavedBreakStatus = new rr::BreakStatus{ *breakStatus };
    }
  }
}

static bool
InterestedInReplayStop(const rr::ReplayResult &result)
{
  return result.break_status.breakpoint_hit || !result.break_status.watchpoints_hit.empty() ||
         result.break_status.signal;
}

static StopKind
DetermineCloneVariant(u64 flags)
{
  if (flags & (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND)) {
    return StopKind::Cloned;
  } else {
    return StopKind::Forked;
  }
}

template <typename UserRegsStructKind>
static std::string
format_user_regs_struct(const UserRegsStructKind &regs)
{
  return std::format("{{ r15: 0x{:x} r14: 0x{:x} r13: 0x{:x} r12: 0x{:x} rbp: 0x{:x} rbx: 0x{:x} r11: 0x{:x} "
                     "r10: 0x{:x} r9: 0x{:x} r8: 0x{:x} rax: 0x{:x} rcx: 0x{:x} rdx: 0x{:x} rsi: 0x{:x} rdi: "
                     "0x{:x} orig_rax: 0x{:x} rip: 0x{:x} cs: {} eflags: {} rsp: 0x{:x} ss: {} fs_base: "
                     "0x{:x} gs_base: 0x{:x} ds: 0x{:x} es: 0x{:x} fs: 0x{:x} gs: 0x{:x} }}",
    regs.r15,
    regs.r14,
    regs.r13,
    regs.r12,
    regs.rbp,
    regs.rbx,
    regs.r11,
    regs.r10,
    regs.r9,
    regs.r8,
    regs.rax,
    regs.rcx,
    regs.rdx,
    regs.rsi,
    regs.rdi,
    regs.orig_rax,
    regs.rip,
    regs.cs,
    regs.eflags,
    regs.rsp,
    regs.ss,
    regs.fs_base,
    regs.gs_base,
    regs.ds,
    regs.es,
    regs.fs,
    regs.gs);
}

StopKind
ReplaySupervisor::CheckStopKind(pid_t recTid, int syscallNumber, const rr::TraceFrame &traceFrame) noexcept
{
  const auto arch = traceFrame.event().Syscall().arch();
  using enum StopKind;
  if (rr::is_clone_syscall(syscallNumber, arch) || is_clone3_syscall(syscallNumber, arch)) {
    // Clone is actually the system call used now-adays, not calling fork etc. So we need to determine if the
    // clone-call is "fork like" by parsing the flags argument.
    u64 flags = 0;
    bool is_clone_3 = !rr::is_clone_syscall(syscallNumber, arch);

    if (!is_clone_3) {
      // for the old clone syscall, `flags` arguments is arg 1, of type uint64_t
      flags = traceFrame.regs().arg1();
    } else {
      // clone3 1st argument is clone_args*, so we need to read tracee memory, where that arg is pointing to and
      // pull out the 1st member of the struct, which is the `flags` arg
      uintptr_t cloneArgsPtr = traceFrame.regs().arg1();
      // structs are well defined in size, but read manpages `man clone3`, possible future extensions
      size_t cloneArgsSize = traceFrame.regs().arg2();
      // flags is 1st member in clone_args, so just read that
      if (cloneArgsPtr == 0) {
        return StopKind::NotKnown;
      }
      if (-1 == ReadMemory(recTid, cloneArgsPtr, sizeof(flags), &flags)) {
        DBGBUFLOG(core, "Failed to read clone_args for clone system calls. That's bad.");
        return StopKind::NotKnown;
      }
    }
    DBGBUFLOG(core,
      "clone (clone3={}) flags: 0x{:x}, regs={}",
      is_clone_3,
      flags,
      format_user_regs_struct(traceFrame.regs().get_ptrace()));
    return DetermineCloneVariant(flags);
  } else if (is_fork_syscall(syscallNumber, arch)) {
    return Forked;
  } else if (is_vfork_syscall(syscallNumber, arch)) {
    return VForked;
  } else if (rr::is_execve_syscall(syscallNumber, arch) || rr::is_execveat_syscall(syscallNumber, arch)) {
    return Execed;
  }

  return StopKind::NotKnown;
}

std::optional<SupervisorEvent>
ReplaySupervisor::FromReplayResult(const rr::ReplayResult &result, ResumeReplay &replayRequest)
{
  StopKind stopKind = StopKind::NotKnown;

  const auto &traceFrame = mTimeline->current_session().last_replayed_trace_frame();

  const auto toInfo = [&](Pid childPid = 0) {
    auto task = static_cast<rr::ReplayTask *>(result.break_status.task());
    if (!task) {
      task = mTimeline->current_session().find_task(traceFrame.tid());
    }
    MDB_ASSERT(task != nullptr, "Could not find task {}", traceFrame.tid());
    return TraceFrameTaskContext::From(
      result.break_status.signal ? result.break_status.signal->si_signo : 0, *task, childPid);
  };

  // check if last replayed_event was a thread group mutating syscall.
  auto &ev = traceFrame.event();
  if (ev.is_syscall_event() && ev.Syscall().state == rr::EXITING_SYSCALL && !traceFrame.regs().syscall_failed()) {
    stopKind = CheckStopKind(result.break_status.task()->rec_tid, ev.Syscall().number, traceFrame);
    if (stopKind >= StopKind::Forked && stopKind <= StopKind::Cloned) {
      DBGBUFLOG(core, "new child is = {}", traceFrame.regs().syscall_result());
      return std::make_optional(
        ReplayEvent{ .mTaskInfo = toInfo(traceFrame.regs().syscall_result()), .mStopKind = stopKind });
    } else if (stopKind == StopKind::Execed) {
      return std::make_optional(ReplayEvent{ .mTaskInfo = toInfo(), .mStopKind = stopKind });
    }
  }

  if (result.break_status.breakpoint_hit || !result.break_status.watchpoints_hit.empty()) {
    return std::make_optional(ReplayEvent{ .mTaskInfo = toInfo(),
      .mStopKind = StopKind::Stopped,
      .mHitBreakpoint = result.break_status.breakpoint_hit,
      .mHitWatchpoint = !result.break_status.watchpoints_hit.empty() });
  }

  if (result.break_status.task_exit) {
    return std::make_optional(ReplayEvent{ .mTaskInfo = toInfo(), .mStopKind = StopKind::Exited });
  }

  if (result.break_status.signal.get() != nullptr) {
    return std::make_optional(ReplayEvent{ .mTaskInfo = toInfo(), .mStopKind = StopKind::Signalled });
  }

  const bool trace_stepping_completed =
    (replayRequest.resume_type == ResumeType::RR_STEP && ((--replayRequest.steps) <= 0));
  if (trace_stepping_completed) {
    return std::make_optional(ReplayEvent{ .mTaskInfo = toInfo(), .mStopKind = StopKind::Stopped });
  }

  return {};
}

rr::ReplayResult
ReplaySupervisor::PerformResume()
{
  mLastRequestedResume = mRequestedResume;
  // TODO: implement reverse single-step
  switch (mRequestedResume->direction) {
  case RR_DIR_FORWARD: {
    return mTimeline->replay_step_forward(mRequestedResume->resume_type == ResumeType::RR_RESUME
                                            ? rr::RunCommand::RUN_CONTINUE
                                            : rr::RunCommand::RUN_SINGLESTEP);
  }
  case RR_DIR_REVERSE: {
    return mTimeline->reverse_continue([](auto, auto) { return true; },
      [&stop_flag = mPendingInterrupt]() { return stop_flag.load(std::memory_order_relaxed); });
  }
  }
  PANIC("Invalid resume request");
}

bool
ReplaySupervisor::InterruptCheck()
{
  if (mPendingInterrupt) {
    SetWillNeedResume(nullptr);
    // No stop event is pending, we will push an "interrupt stop-event"
    rr::ReplayTask *reportTask = nullptr;
    reportTask = mLastPendingInterruptFor == 0 ? mTimeline->current_session().current_task()
                                               : mTimeline->current_session().find_task(mLastPendingInterruptFor);
    // This literally should never happen.
    MDB_ASSERT(reportTask != nullptr, "could not find a task to report for {}", mLastPendingInterruptFor);
    PublishEvent(
      ReplayEvent{ .mTaskInfo = TraceFrameTaskContext::From(0, *reportTask), .mStopKind = StopKind::Stopped });

    mPendingInterrupt = false;
    mLastPendingInterruptFor = 0;
    return true;
  }
  return false;
}

void
ReplaySupervisor::NotifyResumed() noexcept
{
  mHasRequest = true;

  if (!mTimelineSupervisors.empty()) {
    auto *debugAdapterManager = mTimelineSupervisors.front()->GetDebugAdapterProtocolClient();
    for (auto &supervisor : mTimelineSupervisors) {
      if (supervisor->GetSessionId() != -1 && !supervisor->IsExited()) {
        debugAdapterManager->PostDapEvent(new ui::dap::ContinuedEvent{
          supervisor->GetSessionId(), supervisor->TaskLeaderTid(), /* allThreads */ true });
      }
    }
  }

  mRequestCondVar.notify_one();
}

static std::optional<Path>
MdbPath()
{
  char path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (len == -1) {
    perror("readlink");
    return std::nullopt;
  }
  path[len] = '\0'; // Null-terminate the string
  return Path{ path };
}

void
ReplaySupervisor::SpawnSupervisorThread() noexcept
{
  mSupervisorThread = std::jthread([this](const std::stop_token &tok) {
    InitLibrary();
    const auto debuggerBinaryPathResult = MdbPath();
    MDB_ASSERT(debuggerBinaryPathResult.has_value(), "Failed to get mdb executable path");
    rr::Flags::get_for_init().resource_path = debuggerBinaryPathResult->parent_path().string() + "/";
    DBGBUFLOG(core, "Started supervisor thread, initialized resources path to={}", rr::Flags::get().resource_path);
    std::unique_lock lock(mCondVarMutex);
    while (!tok.stop_requested()) {
      // wait for start replay command
      if (!mIssuedStartRequest) {
        DBGLOG(core, "Wait for start to be issued");
        mHasReplayCondVar.wait(lock);
      }

      auto traceDir = mTraceDir;
      if (!fs::exists(traceDir)) {
        // FIXME(!): Remove this hard coding later
        const auto RR_TRACE_DIR = "/home/prometheus/.local/share/rr";
        traceDir = std::format("{}/{}", RR_TRACE_DIR, mTraceDir);
        if (!fs::exists(traceDir)) {
          DBGLOG(core, "Trace directory {} doesn't exist", mTraceDir);
          continue;
        } else {
          DBGLOG(core, "Found trace named {} when looking in RR_TRACE_DIR", mTraceDir);
        }
      }

      DBGLOG(core, "Supervisor starting replay...");
      mReplayOptions = StartReplayOptions{ .trace_dir = traceDir.c_str(), .goto_event = 0 };
      InitializeDebugSession();
      DBGLOG(core, "Replay started!");
      // run actual replay loop
      while (HasSession() && !tok.stop_requested()) {
        WaitForEvent();
        DBGLOG(core, "processing made rr supervisor requests...");
        ProcessRequests();
      }
    }
  });
}

ReplaySupervisor::ReplaySupervisor(const RRInitOptions &initOptions) noexcept : mInitOptions(initOptions) {}

#define MATCH(VARIANT)                                                                                            \
  std::visit(                                                                                                     \
    [&](auto &&event) {                                                                                           \
      using T = std::decay_t<decltype(event)>;                                                                    \
      (void)event;                                                                                                \
    },                                                                                                            \
    VARIANT);

/* static */
ReplaySupervisor *
ReplaySupervisor::Create(SessionId sessionId, const RRInitOptions &initOptions) noexcept
{
  auto supervisor = new ReplaySupervisor{ initOptions };

  // Configure the event handler. The replay supervisor thread will post events, which gets pre-processed here
  // then pushed to the debugger core subsystem
  supervisor->SetEventHandler([](const SupervisorEvent &evt, void *userData) {
    DBGBUFLOG(core, "Run replay session event handler");
    ReplaySupervisor *supervisor = static_cast<ReplaySupervisor *>(userData);
    std::visit(
      [&](auto &&event) {
        using T = std::decay_t<decltype(event)>;
        if constexpr (IsType<T, ReplayEvent>) {
          mdb::EventSystem::Get().PushReplayStopEvent(event);
        } else if constexpr (IsType<T, SessionEvent>) {
          if (supervisor->mSupervisorEvents.contains(event.mType)) {
            supervisor->mSupervisorEvents[event.mType]();
          }
        }
      },
      evt);
  });

  supervisor->SpawnSupervisorThread();

  DBGLOG(core, "Return supervisor handle: {:p}", (void *)supervisor);
  return supervisor;
}

} // namespace mdb::tc::replay
