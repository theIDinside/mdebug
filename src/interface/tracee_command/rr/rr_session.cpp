/** LICENSE TEMPLATE */

#include "rr_session.h"

// rr
#include <ReplayTask.h>
#include <kernel_abi.h>

// mdb
#include <interface/dap/events.h>
#include <interface/tracee_command/rr/rr_supervisor.h>
#include <session_task_map.h>
#include <symbolication/dwarf_binary_reader.h>
#include <task.h>
#include <tracer.h>
#include <utils/todo.h>

namespace mdb::tc::replay {

Session::Session(ReplaySupervisor *replaySupervisor, Tid taskLeader, ui::dap::DebugAdapterManager *dap) noexcept
    : SupervisorState(SupervisorType::RR, taskLeader, dap), mReplaySupervisor(replaySupervisor)
{
}

rr::ReplayTask *
Session::GetReplayTask(Tid recTid) noexcept
{
  return mReplaySupervisor->GetTask(recTid);
}

std::optional<std::string>
Session::GetThreadName(Tid tid) noexcept
{
  auto task = mReplaySupervisor->GetTask(tid);
  if (task) {
    return task->name();
  }
  return {};
}

/* static */
Session *
Session::Create(ReplaySupervisor *replaySupervisor,
  std::optional<SessionId> sessionId,
  Tid taskLeader,
  ui::dap::DebugAdapterManager *dap,
  bool hasReplayedStep) noexcept
{
  if (auto cachedSupervisor = replaySupervisor->CachedSupervisor(taskLeader); cachedSupervisor) {
    MDB_ASSERT(cachedSupervisor->mExited, "Supervisor had not exited and is now created again.");
    cachedSupervisor->mHasFirstExecuted = hasReplayedStep;
    return cachedSupervisor;
  }

  replaySupervisor->RegisterStopsForProcess(taskLeader);
  auto supervisor = std::unique_ptr<Session>(new Session{ replaySupervisor, taskLeader, dap });
  supervisor->mHasFirstExecuted = hasReplayedStep;
  auto ptr = supervisor.get();

  if (sessionId) {
    Tracer::GetDebugAdapterManager().InitializeSession(*sessionId);
    auto session = Tracer::GetDebugAdapterManager().GetSession(*sessionId);
    session->OnCreatedSupervisor(NonNull<tc::SupervisorState>(*ptr));
  }
  Tracer::AddSupervisor(std::move(supervisor));
  replaySupervisor->AddSupervisor(NonNull(*ptr));
  return ptr;
}

ReplaySupervisor *
Session::GetReplaySupervisor() const noexcept
{
  return mReplaySupervisor;
}

void
Session::HandleEvent(const ReplayEvent &evt) noexcept
{
  if (!mHasFirstExecuted) {

    MDB_ASSERT(mParentSessionId.has_value(), "No parent session id");
    DBGBUFLOG(core,
      "Handling first replayable event for process={}. Notifying parent session {}, that a new process exists (to "
      "attach to)",
      mTaskLeader,
      *mParentSessionId);
    mHasFirstExecuted = true;
    mDeferredEvent = evt;
    mDebugAdapterClient->PostDapEvent(new ui::dap::Process{ *mParentSessionId, TaskLeaderTid(), "forked", true });
    return;
  }
  DBGBUFLOG(core, "Handle event {}, recorded tid={}", evt.mStopKind, evt.mTaskInfo.mRecTid);
  auto task = GetTaskByTid(evt.mTaskInfo.mRecTid);

  bool steppedOverBreakpoint = false;

  if (task->mBreakpointLocationStatus.mBreakpointLocation && task->mBreakpointLocationStatus.mIsSteppingOver) {
    steppedOverBreakpoint = true;
    task->mBreakpointLocationStatus.mBreakpointLocation->Enable(task->mTid, *this);
    // Clear breakpoint location status. The existence of this value, means the task needs to step over a
    // breakpoint. Since we've established that we've stepped over one here, we need to clear the loc status, so
    // that the next resume doesn't think it needs stepping over a breakpoint.
    task->ClearBreakpointLocStatus();
  }

  switch (evt.mStopKind) {
  case StopKind::Stopped: {
    if (!task->mHasStarted) {
      mDebugAdapterClient->PostDapEvent(
        new ui::dap::ThreadEvent{ mSessionId, ui::dap::ThreadReason::Started, task->mTid });
      task->mHasStarted = true;
    }
    if (evt.mHitBreakpoint) {
      RefPtr loc = mUserBreakpoints.GetLocationAt(evt.mTaskInfo.mRIP);
      TaskInfo *task = GetTaskByTid(evt.mTaskInfo.mRecTid);
      HandleBreakpointHit(*task, loc);
    } else {
      mScheduler->Schedule(*task, { true, task->mResumeRequest.mType });
    }
  } break;
  case StopKind::Execed: {
    HandleExec(*task, mReplaySupervisor->ExecedFile(task->mTid));
  } break;
  case StopKind::Exited: {
    mDebugAdapterClient->PostDapEvent(
      new ui::dap::ThreadEvent{ mSessionId, ui::dap::ThreadReason::Exited, task->mTid });
  } break;
  case StopKind::Forked:
    [[fallthrough]];
  case StopKind::VForked: {
    if (!mReplaySupervisor->IsIgnoring(evt.mTaskInfo.mNewTaskIfAny)) {
      HandleFork(*task, evt.mTaskInfo.mNewTaskIfAny, evt.mStopKind == StopKind::VForked);
      EmitStopped(task->mTid, ui::dap::StoppedReason::Entry, "Forked", true, {});
    } else {
      mScheduler->Schedule(*task, {});
    }
  } break;
  case StopKind::VForkDone: {
  } break;
  case StopKind::Cloned: {
    auto threadName = GetThreadName(evt.mTaskInfo.mNewTaskIfAny);
    CreateNewTask(evt.mTaskInfo.mNewTaskIfAny, threadName.value_or("thread"), false);
    mScheduler->Schedule(*task, { true, task->mResumeRequest.mType });
  } break;
  case StopKind::Signalled: {
    TODO("StopKind::Signalled");
  } break;
  case StopKind::SyscallEntry: {
    TODO("StopKind::SyscallEntry");
  } break;
  case StopKind::SyscallExit: {
    TODO("StopKind::SyscallExit");
  } break;
  case StopKind::NotKnown: {
  } break;
  }
}

void
Session::HandleFork(TaskInfo &parentTask, pid_t child, bool vFork) noexcept
{
  const bool hasReplayedStep = false;
  auto newSupervisor =
    Session::Create(mReplaySupervisor, std::nullopt, child, mDebugAdapterClient, hasReplayedStep);
  newSupervisor->mParentSessionId = mSessionId;

  // When a replay session forks, we can't actually notify the debugger client that the process exists yet
  // because, doing so, it would try to actually do stuff with it. The process is not safe to be touched by the
  // client until it's first execution step Therefore, defer any notifications of a new process existing, *until*
  // it has first started (it's first replay event in the trace).
  // So where we for native/ptrace sessions inform the client of a new session to be instantiated here, we wait
  // until first replay step for replay sessions.
  if (!vFork) {
    newSupervisor->OnForkFrom(*this);
  } else {
    TODO("Implement vfork - Do I even need to do anything special here? I'm not sure.");
  }
  mScheduler->Schedule(parentTask, { true, parentTask.mResumeRequest.mType });
}

mdb::Expected<Auxv, Error>
Session::DoReadAuxiliaryVector() noexcept
{
  auto auxv = mReplaySupervisor->GetAuxv(mTaskLeader);
  Auxv result{};
  result.mContents.reserve(auxv.size() / (8 * 2));
  for (auto i = 0; i < auxv.size(); i += 16) {
    uint64_t value{};
    uint64_t key{};
    std::memcpy(&key, auxv.data() + i, 8);
    std::memcpy(&value, auxv.data() + i + 8, 8);
    result.mContents.emplace_back(key, value);
  }
  return result;
}

void
Session::InitRegisterCacheFor(const TaskInfo &task) noexcept
{
  // RR supervisors does not need to initialize a register cache, because RR itself, manages task data & metadata,
  // so we will be querying it directly
}

bool
Session::PerformShutdown() noexcept
{
  TODO("Session::PerformShutdown() noexcept");
}

TaskExecuteResponse
Session::InstallBreakpoint(Tid tid, AddrPtr addr) noexcept
{
  bool res = mReplaySupervisor->SetBreakpoint(tid, BreakpointRequest{ .is_hardware = false, .address = addr });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::ReadRegisters(TaskInfo &t) noexcept
{
  // We don't need to read registers here at all (I believe). Because RR will have fetched this for us.
  auto task = mReplaySupervisor->GetTask(t.mTid);
  MDB_ASSERT(task, "No task by that id");
  auto userRegs = task->regs().get_ptrace();
  DBGBUFLOG(core,
    "read registers for {}: [rip:0x{:x}, rsp:0x{:x}, rax:0x{:x}]",
    t.mTid,
    userRegs.rip,
    userRegs.rsp,
    userRegs.rax);
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
Session::WriteRegisters(TaskInfo &t, void *data, size_t length) noexcept
{
  // Diversion sessions not supported (and may never be supported.)
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::SetRegister(TaskInfo &t, size_t registerNumber, void *data, size_t length) noexcept
{
  return TaskExecuteResponse::Error(-1);
}

u64
Session::GetUserRegister(const TaskInfo &t, size_t registerNumber) noexcept
{
  // this should be safe rr::NativeArch::user_regs_struct -> user_regs_struct
  const auto internalData = mReplaySupervisor->GetTask(t.mTid)->regs().get_regs_for_trace();
  const auto index = GetDwarfRegisterIndex(registerNumber);
  auto *ptr = reinterpret_cast<const u64 *>(internalData.data);
  return *(ptr + index);
}

TaskExecuteResponse
Session::DoDisconnect(bool terminate) noexcept
{
  TODO(R"(
    - Disconnect from "this" session.
    - Register this session as "ignored / disconnected" with ReplaySupervisor
    - If A: this is the only session tracked/replayed, terminate entire debug session
    - Else B: ignore events belonging to this session/process in the replay from now on
    )");
}

ReadResult
Session::DoReadBytes(AddrPtr address, u32 size, u8 *readBuffer) noexcept
{
  const auto result = mReplaySupervisor->ReadMemory(mTaskLeader, address, size, readBuffer);
  if (result == -1) {
    return ReadResult::AppError(ApplicationError::TargetIsRunning);
  }

  return ReadResult::Ok((u32)result);
}

TraceeWriteResult
Session::DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept
{
  TODO("Session::DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept");
}

TaskExecuteResponse
Session::EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  bool res = mReplaySupervisor->SetBreakpoint(
    tid, BreakpointRequest{ .is_hardware = false, .address = location.Address() });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  bool res = mReplaySupervisor->RemoveBreakpoint(
    tid, BreakpointRequest{ .is_hardware = false, .address = location.Address() });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::StopTask(TaskInfo &t) noexcept
{
  // Supervisor does single threaded execution, interrupting all is interrupting `t`
  mReplaySupervisor->RequestInterrupt(mTaskLeader);
  return TaskExecuteResponse::Ok();
}

void
Session::DoResumeTask(TaskInfo &t, RunType runType) noexcept
{
  DBGLOG(core, "Attempting to resume task {}", t.mTid);
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  if (runType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
    resumeReplay.steps = 1;
  }

  mReplaySupervisor->RequestResume(resumeReplay);
}

bool
Session::DoResumeTarget(RunType runType) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  if (runType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
  }

  auto taskToResume = mReplaySupervisor->GetTaskToResume();
  DBGLOG(core, "Resuming replay, current task={}", taskToResume);

  auto task = GetTaskByTid(taskToResume);

  if (task->mBreakpointLocationStatus.IsValid()) {
    task->StepOverBreakpoint();
    return true;
  }

  return mReplaySupervisor->RequestResume(resumeReplay);
}

bool
Session::ReverseResumeTarget(tc::RunType runType) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_REVERSE };

  if (runType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
  }

  bool ok = mReplaySupervisor->RequestResume(resumeReplay);
  if (!ok) {
    return false;
  }

  // We never
  for (auto &t : GetThreads()) {
    t.mTask->ClearBreakpointLocStatus();
    t.mTask->SetInvalidCache();
  }
  return true;
}

void
Session::AttachSession(ui::dap::DebugAdapterSession &session) noexcept
{
  session.OnCreatedSupervisor(NonNull<tc::SupervisorState>(*this));
  OnConfigurationDone([](tc::SupervisorState *_supervisor) {
    auto *supervisor = static_cast<Session *>(_supervisor);
    supervisor->HandleEvent(supervisor->mDeferredEvent.value());
    return true;
  });
}

bool
Session::Pause(Tid tid) noexcept
{
  if (!mReplaySupervisor->IsReplaying()) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::StoppedEvent{
      mSessionId, ui::dap::StoppedReason::Pause, "Paused", tid, {}, "Paused all", true });
    return true;
  }
  auto task = GetTaskByTid(tid);
  if (task->IsStopped()) {
    return false;
  }
  const bool success = SetAndCallRunAction(
    task->mTid, std::make_shared<ptracestop::StopImmediately>(*this, *task, ui::dap::StoppedReason::Pause));
  return success;
}

} // namespace mdb::tc::replay