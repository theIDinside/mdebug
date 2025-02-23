/** LICENSE TEMPLATE */
#include "task.h"
#include "fmt/ranges.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "register_description.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/value.h"
#include "utils/logger.h"
#include "utils/util.h"
#include <mdbsys/ptrace.h>
#include <sys/user.h>
#include <tracee/util.h>
#include <tracer.h>
#include <utility>

namespace mdb {
TaskRegisters::TaskRegisters(TargetFormat format, gdb::ArchictectureInfo *archInfo) : mRegisterFormat(format)
{
  switch (mRegisterFormat) {
  case TargetFormat::Native:
    registers = new user_regs_struct{};
    break;
  case TargetFormat::Remote:
    ASSERT(archInfo, "Architecture info must be present for remote targets!");
    registerFile = new RegisterDescription{archInfo};
    break;
  }
}

AddrPtr
TaskRegisters::GetPc() const noexcept
{
  switch (mRegisterFormat) {
  case TargetFormat::Native:
    return registers->rip;
  case TargetFormat::Remote:
    return registerFile->GetPc();
  }
  NEVER("Unknown register format");
}

u64
TaskRegisters::GetRegister(u32 regNumber) const noexcept
{
  switch (mRegisterFormat) {
  case TargetFormat::Native:
    return get_register(registers, regNumber);
  case TargetFormat::Remote:
    static_assert(mdb::castenum(ArchType::COUNT) == 1, "Supported architectures have increased");
    return registerFile->GetRegister(regNumber);
    break;
  }
  NEVER("Unknown target format");
}

TaskInfo::TaskInfo(pid_t newTaskTid) noexcept
    : mTid(newTaskTid), mLastWaitStatus(), mUserVisibleStop(true), mTracerVisibleStop(true), initialized(false),
      exited(false), reaped(false), regs(), mTaskCallstack(nullptr), mSupervisor(nullptr),
      mBreakpointLocationStatus()

{
}

TaskInfo::TaskInfo(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isUserStopped) noexcept
    : mTid(newTaskTid), mLastWaitStatus(), mUserVisibleStop(isUserStopped), mTracerVisibleStop(true),
      initialized(true), exited(false), reaped(false), regs(supervisor.mFormat, supervisor.mArchInfo.Cast().get()),
      mSupervisor(supervisor.GetSupervisor()), mBreakpointLocationStatus()
{
  mTaskCallstack = std::make_unique<sym::CallStack>(supervisor.GetSupervisor(), this);
}

void
TaskInfo::InitializeThread(tc::TraceeCommandInterface &tc, bool restart) noexcept
{
  ASSERT(mTaskCallstack == nullptr && initialized == false, "Thread has already been initialized.");
  mUserVisibleStop = true;
  mTracerVisibleStop = true;
  initialized = true;
  mRegisterCacheDirty = true;
  mInstructionPointerDirty = true;
  exited = false;
  reaped = false;
  regs = {tc.mFormat, tc.mArchInfo.Cast().get()};
  mBreakpointLocationStatus = {};
  mTaskCallstack = std::make_unique<sym::CallStack>(tc.GetSupervisor(), this);
  mSupervisor = tc.GetSupervisor();
  ASSERT(mSupervisor != nullptr, "must have supervisor");
  DBGLOG(core, "Deferred initializing of thread {} completed", mTid);
  if (restart) {
    EventSystem::Get().PushDebuggerEvent(TraceEvent::CreateThreadCreated(
      {tc.TaskLeaderTid(), mTid, 5, 0}, {tc::RunType::Continue, tc::ResumeTarget::Task, 0}, {}));
  }
}

/*static*/
Ref<TaskInfo>
TaskInfo::CreateTask(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isRunning) noexcept
{
  DBGLOG(core, "creating task {}.{}: running={}", supervisor.TaskLeaderTid(), newTaskTid, isRunning);
  return RcHandle<TaskInfo>::MakeShared(supervisor, newTaskTid, !isRunning);
}

/** static */
Ref<TaskInfo>
TaskInfo::CreateUnInitializedTask(TaskWaitResult wait) noexcept
{
  auto task = Ref<TaskInfo>{new TaskInfo{wait.tid}};
  Tracer::Get().RegisterTracedTask(task);
  task->mLastWaitStatus = wait.ws;
  return task;
}

user_regs_struct *
TaskInfo::NativeRegisters() const noexcept
{
  ASSERT(regs.mRegisterFormat == TargetFormat::Native, "Used in the wrong context");
  return regs.registers;
}

RegisterDescription *
TaskInfo::RemoteX86Registers() const noexcept
{
  ASSERT(regs.mRegisterFormat == TargetFormat::Remote, "Used in the wrong context");
  return regs.registerFile;
}

void
TaskInfo::RemoteFromHexdigitEncoding(std::string_view hex_encoded) noexcept
{
  ASSERT(regs.mRegisterFormat == TargetFormat::Remote, "Expected remote format");

  regs.registerFile->FillFromHexEncodedString(hex_encoded);
  SetUpdated();
}

const TaskRegisters &
TaskInfo::GetRegisterCache() const
{
  return regs;
}

u64
TaskInfo::GetRegister(u64 reg_num) noexcept
{
  return regs.GetRegister(reg_num);
}

u64
TaskInfo::UnwindBufferRegister(u8 level, u16 register_number) const noexcept
{
  return mTaskCallstack->UnwindRegister(level, register_number);
}

void
TaskInfo::StoreToRegisterCache(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept
{
  regs.registerFile->Store(data);
}

#define RETURN_RET_ADDR_IF(cond)                                                                                  \
  if ((cond))                                                                                                     \
    return mTaskCallstack->ReturnAddresses();

#define RETURN_RET_ADDR_LOG(cond, ...)                                                                            \
  if ((cond)) {                                                                                                   \
    DBGLOG(core, __VA_ARGS__);                                                                                    \
    return mTaskCallstack->ReturnAddresses();                                                                     \
  }

std::span<const AddrPtr>
TaskInfo::UnwindReturnAddresses(TraceeController *tc, CallStackRequest req) noexcept
{
  RETURN_RET_ADDR_IF(!mTaskCallstack->IsDirty());

  tc->CacheRegistersFor(*this);
  // initialize bottom frame's registers with actual live register contents
  // this is then used to execute the dwarf binary code
  mTaskCallstack->Unwind(req);
  return mTaskCallstack->ReturnAddresses();
}

sym::FrameUnwindState *
TaskInfo::GetUnwindState(int frameLevel) noexcept
{
  return mTaskCallstack->GetUnwindState(static_cast<u32>(frameLevel));
}

TraceeController *
TaskInfo::GetSupervisor() const noexcept
{
  return mSupervisor;
}

void
TaskInfo::set_taskwait(TaskWaitResult wait) noexcept
{
  mLastWaitStatus = wait.ws;
}

WaitStatus
TaskInfo::PendingWaitStatus() const noexcept
{
  ASSERT(mLastWaitStatus.ws != WaitStatusKind::NotKnown, "Wait status unknown for {}", mTid);
  return mLastWaitStatus;
}

sym::CallStack &
TaskInfo::GetCallstack() noexcept
{
  return *mTaskCallstack;
}

bool
TaskInfo::VariableReferenceIsStale(VariableReferenceId value) const noexcept
{
  return !(value >= mLivenessBoundary);
}

void
TaskInfo::SetValueLiveness(VariableReferenceId value) noexcept
{
  mLivenessBoundary = value;
}

void
TaskInfo::AddReference(VariableReferenceId id) noexcept
{
  variableReferences.push_back(id);
}

void
TaskInfo::CacheValueObject(VariableReferenceId ref, Ref<sym::Value> value) noexcept
{
  mVariablesCache.emplace(ref, std::move(value));
}

Ref<sym::Value>
TaskInfo::GetVariablesReference(u32 ref) noexcept
{
  auto it = mVariablesCache.find(ref);
  if (it == std::end(mVariablesCache)) {
    return nullptr;
  }
  return it->second;
}

void
TaskInfo::RequestedStop() noexcept
{
  bfRequestedStop = true;
}

void
TaskInfo::ClearRequestedStopFlag() noexcept
{
  bfRequestedStop = false;
}

void
TaskInfo::SetTracerState(SupervisorState state) noexcept
{
  mState = state;
}

std::optional<Pid>
TaskInfo::GetTaskLeaderTid() const noexcept
{
  if (mSupervisor == nullptr) {
    return {};
  }

  return mSupervisor->TaskLeaderTid();
}

void
TaskInfo::SetSessionId(u32 sessionId) noexcept
{
  mSessionId = sessionId;
}

void
TaskInfo::StepOverBreakpoint(TraceeController *tc, tc::ResumeAction resume) noexcept
{
  ASSERT(mBreakpointLocationStatus.has_value(), "Requires a valid bpstat");

  auto loc = tc->GetUserBreakpoints().location_at(mBreakpointLocationStatus->loc);
  auto user_ids = loc->loc_users();
  DBGLOG(core, "[TaskInfo {}] Stepping over bps {} at {}", mTid, fmt::join(user_ids, ", "), loc->address());

  auto &control = tc->GetInterface();
  loc->disable(mTid, control);
  mBreakpointLocationStatus->stepped_over = true;
  mBreakpointLocationStatus->re_enable_bp = true;
  mBreakpointLocationStatus->should_resume = resume.type != tc::RunType::None;

  mNextResumeAction = resume;

  const auto result = control.ResumeTask(*this, tc::ResumeAction{tc::RunType::Step, resume.target, 0});
  ASSERT(result.is_ok(), "Failed to step over breakpoint");
}

void
TaskInfo::SetStop() noexcept
{
  mUserVisibleStop = true;
  mTracerVisibleStop = true;
}

void
TaskInfo::SetCurrentResumeAction(tc::ResumeAction type) noexcept
{
  mHasProcessedStop = false;
  mUserVisibleStop = false;
  mTracerVisibleStop = false;
  mLastResumeAction = type;
  SetInvalidCache();
}

bool
TaskInfo::CanContinue() noexcept
{
  return initialized && (mUserVisibleStop || mTracerVisibleStop) && !reaped;
}

void
TaskInfo::SetInvalidCache() noexcept
{
  mRegisterCacheDirty = true;
  mInstructionPointerDirty = true;
  mTaskCallstack->SetDirty();
  // Clear the variables reference cache
  for (const auto ref : variableReferences) {
    Tracer::Get().DestroyVariablesReference(ref);
  }

  variableReferences.clear();
  mVariablesCache.clear();
}

void
TaskInfo::SetUpdated() noexcept
{
  mInstructionPointerDirty = false;
  mRegisterCacheDirty = false;
}

void
TaskInfo::AddBreakpointLocationStatus(AddrPtr address) noexcept
{
  mBreakpointLocationStatus =
    LocationStatus{.loc = address, .should_resume = false, .stepped_over = false, .re_enable_bp = false};
}

std::optional<LocationStatus>
TaskInfo::ClearBreakpointLocStatus() noexcept
{
  const auto copy = mBreakpointLocationStatus;
  mBreakpointLocationStatus = std::nullopt;
  return copy;
}

bool
TaskInfo::IsStopped() const noexcept
{
  return mUserVisibleStop;
}

bool
TaskInfo::IsStopProcessed() const noexcept
{
  return mHasProcessedStop;
}

void
TaskInfo::CollectStop() noexcept
{
  mHasProcessedStop = true;
  mTracerVisibleStop = true;
}

TaskVMInfo
TaskVMInfo::from_clone_args(const clone_args &cl_args) noexcept
{
  return {.stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls};
}

/*static*/ CallStackRequest
CallStackRequest::partial(int count) noexcept
{
  return CallStackRequest{.req = Type::Partial, .count = count};
}

/*static*/ CallStackRequest
CallStackRequest::full() noexcept
{
  return CallStackRequest{.req = Type::Full, .count = 0};
}
} // namespace mdb