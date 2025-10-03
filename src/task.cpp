/** LICENSE TEMPLATE */
#include "task.h"
#include "common/typedefs.h"
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
    : mTid(newTaskTid), mLastStopStatus(), mUserVisibleStop(true), mTracerVisibleStop(true), mInitialized(false),
      mExited(false), mReaped(false), regs(), mTaskCallstack(nullptr), mSupervisor(nullptr),
      mBreakpointLocationStatus()

{
}

TaskInfo::TaskInfo(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isUserStopped) noexcept
    : mTid(newTaskTid), mLastStopStatus(), mUserVisibleStop(isUserStopped), mTracerVisibleStop(true),
      mInitialized(true), mExited(false), mReaped(false),
      regs(supervisor.mFormat, supervisor.mArchInfo.Cast().get()), mSupervisor(supervisor.GetSupervisor()),
      mBreakpointLocationStatus()
{
  mTaskCallstack = std::make_unique<sym::CallStack>(supervisor.GetSupervisor(), this);
}

void
TaskInfo::InitializeThread(tc::TraceeCommandInterface &tc, bool restart) noexcept
{
  MDB_ASSERT(mTaskCallstack == nullptr && mInitialized == false, "Thread has already been initialized.");
  mUserVisibleStop = true;
  mTracerVisibleStop = true;
  mInitialized = true;
  mRegisterCacheDirty = true;
  mInstructionPointerDirty = true;
  mExited = false;
  mReaped = false;
  regs = { tc.mFormat, tc.mArchInfo.Cast().get() };
  mBreakpointLocationStatus = {};
  mTaskCallstack = std::make_unique<sym::CallStack>(tc.GetSupervisor(), this);
  mSupervisor = tc.GetSupervisor();
  mResumeRequest = { tc::RunType::Continue, 0 };
  MDB_ASSERT(mSupervisor != nullptr, "must have supervisor");
  DBGLOG(core, "Deferred initializing of thread {} completed", mTid);
  if (restart) {
    auto *traceEvent = new TraceEvent{ *this };
    TraceEvent::InitThreadCreated(traceEvent, { tc.TaskLeaderTid(), mTid, 5, 0 }, tc::RunType::Continue, {});
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

std::string
format_user_regs_struct(const user_regs_struct &regs)
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

void
TaskInfo::SetRegisterCacheTo(u8 *buffer, size_t bufferSize)
{
  MDB_ASSERT(bufferSize == sizeof(*GetRegisterCache().registers),
    "Buffer size does not match sizeof({})",
    sizeof(*GetRegisterCache().registers));
  regs.registers = reinterpret_cast<user_regs_struct *>(buffer);
  DBGLOG(core, "[task:{}][registers]: {}", mTid, format_user_regs_struct(*regs.registers));
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
TaskInfo::UnwindReturnAddresses(CallStackRequest req) noexcept
{
  RETURN_RET_ADDR_IF(!mTaskCallstack->IsDirty());

  mSupervisor->CacheRegistersFor(*this);
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
  mRequestedStop = true;
}

void
TaskInfo::ClearRequestedStopFlag() noexcept
{
  mRequestedStop = false;
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
TaskInfo::SetResumeType(tc::RunType type) noexcept
{
  mResumeRequest.mType = type;
}

void
TaskInfo::SetForwardedSignal(int signal) noexcept
{
  mResumeRequest.mSignal = signal;
}

std::optional<int>
TaskInfo::ConsumeSignal() noexcept
{
  if (mResumeRequest.mSignal != 0) {
    const int signal = mResumeRequest.mSignal;
    mResumeRequest.mSignal = 0;
    return signal;
  }
  return {};
}

void
TaskInfo::StepOverBreakpoint() noexcept
{
  MDB_ASSERT(mBreakpointLocationStatus.IsValid(), "Requires a valid bpstat");

  auto userBreakpointIds = mBreakpointLocationStatus.mBreakpointLocation->GetUserIds();
  DBGLOG(core,
    "[TaskInfo {}] Stepping over bps {} at {}",
    mTid,
    JoinFormatIterator{ userBreakpointIds, ", " },
    mBreakpointLocationStatus.mBreakpointLocation->Address());

  auto &control = mSupervisor->GetInterface();
  mBreakpointLocationStatus.mBreakpointLocation->Disable(mTid, control);
  mBreakpointLocationStatus.mIsSteppingOver = true;
  const auto result = control.ResumeTask(*this, tc::RunType::Step);

  MDB_ASSERT(result.is_ok(), "Failed to step over breakpoint");
}

void
TaskInfo::SetUserVisibleStop() noexcept
{
  mUserVisibleStop = true;
  mTracerVisibleStop = true;
}

void
TaskInfo::SetIsRunning() noexcept
{
  mUserVisibleStop = false;
  mTracerVisibleStop = false;
  SetInvalidCache();
}

bool
TaskInfo::CanContinue() noexcept
{
  return mInitialized && (mUserVisibleStop || mTracerVisibleStop) && !mReaped;
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
  return mTracerVisibleStop;
}

void
TaskInfo::CollectStop() noexcept
{
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