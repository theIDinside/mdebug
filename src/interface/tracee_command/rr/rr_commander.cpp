/** LICENSE TEMPLATE */
#include "rr_commander.h"

// mdb
#include <bp.h>
#include <interface/rr/rr_supervisor.h>
#include <interface/tracee_command/tracee_command_interface.h>
#include <supervisor.h>
#include <task.h>

// rr includes
#include <ReplayTask.h>

namespace mdb::tc {

mdbrr::ReplaySupervisor *
RR::GetSupervisor() noexcept
{
  return mReplaySupervisor;
}

RR::RR(Tid taskLeaderId, mdbrr::ReplaySupervisor *replaySupervisor) noexcept
    : TraceeCommandInterface(TargetFormat::Native, nullptr, TraceeInterfaceType::RR),
      mReplaySupervisor(replaySupervisor), mTaskLeader(taskLeaderId)
{
}

ReadResult
RR::ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept
{
  const auto read_bytes =
    GetSupervisor()->ReadMemory(mTaskLeader, address.GetRaw(), static_cast<ssize_t>(size), (void *)read_buffer);
  if (read_bytes < 0) {
    return ReadResult::AppError(ApplicationError::TargetIsRunning);
  }
  const auto cast = static_cast<u32>(read_bytes);
  return ReadResult::Ok(cast);
}

TraceeWriteResult
RR::WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept
{
  // Diversion sessions not supported yet.
  return TraceeWriteResult::Error(-1);
}

TaskExecuteResponse
RR::ResumeTask(TaskInfo &t, RunType resumeType) noexcept
{
  DBGLOG(core, "Attempting to resume task {}", t.mTid);
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  if (resumeType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
    resumeReplay.steps = 1;
  }

  bool ok = GetSupervisor()->RequestResume(resumeReplay);

  if (!ok) {
    return TaskExecuteResponse::Error(-1);
  }

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
RR::ResumeTarget(RunType resumeType, std::vector<Tid> *resumedThreads /* Has default value */) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  if (resumeType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
  }

  auto taskToResume = GetSupervisor()->GetTaskToResume();
  DBGLOG(core, "Resuming replay, current task={}", taskToResume);

  auto task = mControl->GetTaskByTid(taskToResume);

  if (task->mBreakpointLocationStatus.IsValid()) {
    task->StepOverBreakpoint();
    return TaskExecuteResponse::Ok();
  }

  bool ok = mReplaySupervisor->RequestResume(resumeReplay);

  if (!ok) {
    return TaskExecuteResponse::Error(-1);
  }

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
RR::ReverseContinue(bool onlyStep) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_REVERSE };

  if (onlyStep) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
  }

  bool ok = GetSupervisor()->RequestResume(resumeReplay);
  if (!ok) {
    return TaskExecuteResponse::Error(-1);
  }

  // We never
  for (auto &t : mControl->GetThreads()) {
    t.mTask->ClearBreakpointLocStatus();
    t.mTask->SetInvalidCache();
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
RR::StopTask(TaskInfo &t) noexcept
{
  // Supervisor does single threaded execution, interrupting all is interrupting `t`
  GetSupervisor()->RequestInterrupt(mTaskLeader);
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
RR::EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  bool res = GetSupervisor()->SetBreakpoint(
    tid, mdbrr::BreakpointRequest{ .is_hardware = false, .address = location.Address() });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
RR::DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  bool res = GetSupervisor()->RemoveBreakpoint(
    tid, mdbrr::BreakpointRequest{ .is_hardware = false, .address = location.Address() });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

// Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
// that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
TaskExecuteResponse
RR::InstallBreakpoint(Tid tid, AddrPtr addr) noexcept
{
  bool res =
    GetSupervisor()->SetBreakpoint(tid, mdbrr::BreakpointRequest{ .is_hardware = false, .address = addr });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
RR::ReadRegisters(TaskInfo &t) noexcept
{
  auto internalData = GetSupervisor()->ReadRegisters(t.mTid);
  t.SetRegisterCacheTo((u8 *)internalData.buf, internalData.cache_size);
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
RR::WriteRegisters(const user_regs_struct &input) noexcept
{
  // Diversion sessions not supported yet.
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
RR::SetProgramCounter(const TaskInfo &t, AddrPtr addr) noexcept
{
  // Diversion sessions not supported yet.
  return TaskExecuteResponse::Error(-1);
}

std::string_view
RR::GetThreadName(Tid tid) noexcept
{
  rr::ReplayTask *task = GetSupervisor()->GetTask(tid);
  if (!mThreadNames.contains(tid)) {
    mThreadNames.emplace(tid, task->name());
  }
  return mThreadNames[tid];
}

TaskExecuteResponse
RR::Disconnect(bool kill_target) noexcept
{
  TODO("not implemented");
}

bool
RR::PerformShutdown() noexcept
{
  TODO("not implemented");
}

/// Re-open proc fs mem file descriptor. Configure
bool
RR::OnExec() noexcept
{
  TODO("not implemented");
}

// Called after a fork for the creation of a new process supervisor
Interface
RR::OnFork(SessionId pid) noexcept
{
  TODO("not implemented");
}

bool
RR::PostFork(TraceeController *parent) noexcept
{
  TODO("not implemented");
}

Tid
RR::TaskLeaderTid() const noexcept
{
  return mTaskLeader;
}

std::optional<Path>
RR::ExecedFile() noexcept
{
  auto path = GetSupervisor()->ExecedFile(mTaskLeader);

  if (path == nullptr) {
    DBGLOG(core, "Replay supervisor returned null for exec'ed file!");
    return {};
  }

  return Path{ path };
}

std::optional<std::vector<ObjectFileDescriptor>>
RR::ReadLibraries() noexcept
{
  DBGLOG(core, "RR::ReadLibraries() not implemented yet, will return empty list");
  return {};
}

std::shared_ptr<gdb::RemoteConnection>
RR::RemoteConnection() noexcept
{
  return nullptr;
}

mdb::Expected<Auxv, Error>
RR::ReadAuxiliaryVector() noexcept
{
  const auto &auxv = GetSupervisor()->GetAuxv(mTaskLeader);
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
RR::OnTaskCreated(TaskInfo &task) noexcept
{
  task.mHasStarted = true;
  mControl->ScheduleResume(task, task.mResumeRequest.mType);
}

void
RR::OnTaskExit(TaskInfo &task) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  bool ok = GetSupervisor()->RequestResume(resumeReplay);
}

RefPtr<TaskInfo>
RR::CreateNewTask(Tid tid, bool isRunning) noexcept
{
  DBGBUFLOG(core, "Create new task={}, cached={}", tid, mTraceThreads.contains(tid));
  // Task has already been created, return that one.
  if (mTraceThreads.contains(tid)) {
    return mTraceThreads[tid];
  }

  // Create new task
  auto task = TaskInfo::CreateTask(*this, tid, isRunning);
  mTraceThreads[tid] = task;
  Tracer::Get().RegisterTracedTask(task);
  return task;
}

} // namespace mdb::tc