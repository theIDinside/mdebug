/** LICENSE TEMPLATE */
#include "task.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "register_description.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/value.h"
#include <mdbsys/ptrace.h>
#include <sys/user.h>
#include <tracee/util.h>
#include <tracer.h>
#include <utility>
#include <utils/format_utils.h>
#include <utils/logger.h>
#include <utils/util.h>

namespace mdb {
TaskRegisters::TaskRegisters(TargetFormat format, gdb::ArchictectureInfo *archInfo) : mRegisterFormat(format)
{
  switch (mRegisterFormat) {
  case TargetFormat::Native:
    registers = new user_regs_struct{};
    break;
  case TargetFormat::Remote:
    MDB_ASSERT(archInfo, "Architecture info must be present for remote targets!");
    registerFile = new RegisterDescription{ archInfo };
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
    : mTid(newTaskTid), mLastStopStatus(), mUserVisibleStop(true), mTracerVisibleStop(true), initialized(false),
      exited(false), reaped(false), regs(), mTaskCallstack(nullptr), mSupervisor(nullptr),
      mBreakpointLocationStatus()

{
}

TaskInfo::TaskInfo(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isUserStopped) noexcept
    : mTid(newTaskTid), mLastStopStatus(), mUserVisibleStop(isUserStopped), mTracerVisibleStop(true),
      initialized(true), exited(false), reaped(false), regs(supervisor.mFormat, supervisor.mArchInfo.Cast().get()),
      mSupervisor(supervisor.GetSupervisor()), mBreakpointLocationStatus()
{
  mTaskCallstack = std::make_unique<sym::CallStack>(supervisor.GetSupervisor(), this);
}

void
TaskInfo::InitializeThread(tc::TraceeCommandInterface &tc, bool restart) noexcept
{
  MDB_ASSERT(mTaskCallstack == nullptr && initialized == false, "Thread has already been initialized.");
  mUserVisibleStop = true;
  mTracerVisibleStop = true;
  initialized = true;
  mRegisterCacheDirty = true;
  mInstructionPointerDirty = true;
  exited = false;
  reaped = false;
  regs = { tc.mFormat, tc.mArchInfo.Cast().get() };
  mBreakpointLocationStatus = {};
  mTaskCallstack = std::make_unique<sym::CallStack>(tc.GetSupervisor(), this);
  mSupervisor = tc.GetSupervisor();
  MDB_ASSERT(mSupervisor != nullptr, "must have supervisor");
  DBGLOG(core, "Deferred initializing of thread {} completed", mTid);
  if (restart) {
    auto *traceEvent = new TraceEvent{ *this };
    TraceEvent::InitThreadCreated(
      traceEvent, { tc.TaskLeaderTid(), mTid, 5, 0 }, { tc::RunType::Continue, tc::ResumeTarget::Task, 0 }, {});
    EventSystem::Get().PushDebuggerEvent(traceEvent);
  }
}

/*static*/
Ref<TaskInfo>
TaskInfo::CreateTask(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isRunning) noexcept
{
  DBGLOG(core, "creating task {}.{}: running={}", supervisor.TaskLeaderTid(), newTaskTid, isRunning);
  return RefPtr<TaskInfo>::MakeShared(supervisor, newTaskTid, !isRunning);
}

/** static */
Ref<TaskInfo>
TaskInfo::CreateUnInitializedTask(WaitPidResult wait) noexcept
{
  auto task = RefPtr<TaskInfo>::MakeShared(wait.tid);
  Tracer::Get().RegisterTracedTask(task);
  task->mLastStopStatus = wait.ws;
  return task;
}

user_regs_struct *
TaskInfo::NativeRegisters() const noexcept
{
  MDB_ASSERT(regs.mRegisterFormat == TargetFormat::Native, "Used in the wrong context");
  return regs.registers;
}

RegisterDescription *
TaskInfo::RemoteX86Registers() const noexcept
{
  MDB_ASSERT(regs.mRegisterFormat == TargetFormat::Remote, "Used in the wrong context");
  return regs.registerFile;
}

void
TaskInfo::RemoteFromHexdigitEncoding(std::string_view hex_encoded) noexcept
{
  MDB_ASSERT(regs.mRegisterFormat == TargetFormat::Remote, "Expected remote format");

  regs.registerFile->FillFromHexEncodedString(hex_encoded);
  SetUpdated();
}

const TaskRegisters &
TaskInfo::GetRegisterCache() const
{
  return regs;
}

void
TaskInfo::SetRegisterCacheTo(u8 *buffer, size_t bufferSize)
{
  MDB_ASSERT(bufferSize == sizeof(*GetRegisterCache().registers),
    "Buffer size does not match sizeof({})",
    sizeof(*GetRegisterCache().registers));
  regs.registers = reinterpret_cast<user_regs_struct *>(buffer);
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

void
TaskInfo::RefreshRegisterCache() noexcept
{
  mSupervisor->CacheRegistersFor(*this);
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
TaskInfo::SetTaskWait(WaitPidResult wait) noexcept
{
  mLastStopStatus = wait.ws;
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
TaskInfo::StepOverBreakpoint(TraceeController *tc, tc::RunType resumeType) noexcept
{
  MDB_ASSERT(mBreakpointLocationStatus.IsValid(), "Requires a valid bpstat");

  auto userBreakpointIds = mBreakpointLocationStatus.mBreakpointLocation->GetUserIds();
  DBGLOG(core,
    "[TaskInfo {}] Stepping over bps {} at {}",
    mTid,
    JoinFormatIterator{ userBreakpointIds, ", " },
    mBreakpointLocationStatus.mBreakpointLocation->Address());

  auto &control = tc->GetInterface();
  mBreakpointLocationStatus.mBreakpointLocation->Disable(mTid, control);
  mBreakpointLocationStatus.SetSteppingOver(resumeType);

  const auto result = control.ResumeTask(*this, tc::ResumeAction{ tc::RunType::Step, tc::ResumeTarget::Task, 0 });

  MDB_ASSERT(result.is_ok(), "Failed to step over breakpoint");
}

void
TaskInfo::SetUserVisibleStop() noexcept
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
TaskInfo::AddBreakpointLocationStatus(BreakpointLocation *breakpointLocation) noexcept
{
  MDB_ASSERT(!mBreakpointLocationStatus.IsValid(), "Overwriting breakpoint location status breaks the invariant");
  mBreakpointLocationStatus.Clear();
  mBreakpointLocationStatus.mBreakpointLocation = RefPtr{ breakpointLocation };
}

void
TaskInfo::ClearBreakpointLocStatus() noexcept
{
  mBreakpointLocationStatus.Clear();
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
  return { .stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls };
}

/*static*/ CallStackRequest
CallStackRequest::partial(int count) noexcept
{
  return CallStackRequest{ .req = Type::Partial, .count = count };
}

/*static*/ CallStackRequest
CallStackRequest::full() noexcept
{
  return CallStackRequest{ .req = Type::Full, .count = 0 };
}
} // namespace mdb