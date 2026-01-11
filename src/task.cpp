/** LICENSE TEMPLATE */
#include "task.h"

// mdb
#include <common/typedefs.h>
#include <event_queue_types.h>
#include <interface/tracee_command/supervisor_state.h>
#include <mdbsys/ptrace.h>
#include <symbolication/callstack.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/value.h>
#include <tracee/util.h>
#include <tracer.h>
#include <utils/format_utils.h>
#include <utils/logger.h>
#include <utils/util.h>

// system
#include <sys/user.h>

namespace mdb {

TaskInfo::~TaskInfo() noexcept = default;

TaskInfo::TaskInfo(tc::SupervisorState &supervisor, pid_t newTaskTid) noexcept
    : mTid(newTaskTid), mTaskCallstack(std::make_unique<sym::CallStack>(&supervisor, this)),
      mSupervisor(&supervisor), mBreakpointLocationStatus()
{
}

/*static*/
Ref<TaskInfo>
TaskInfo::CreateTask(tc::SupervisorState &supervisor, pid_t newTaskTid) noexcept
{
  DBGLOG(core, "creating task {}.{}", supervisor.TaskLeaderTid(), newTaskTid);
  return RefPtr<TaskInfo>::MakeShared(supervisor, newTaskTid);
}

AddrPtr
TaskInfo::GetPc() const noexcept
{
  return mSupervisor->GetUserRegister(*this, 16);
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

u64
TaskInfo::GetDwarfRegister(u64 registerNumber) noexcept
{
  return mSupervisor->GetUserRegister(*this, registerNumber);
}

u64
TaskInfo::UnwindBufferRegister(u8 level, u16 register_number) const noexcept
{
  return mTaskCallstack->UnwindRegister(level, register_number);
}

void
TaskInfo::RefreshRegisterCache() noexcept
{
  mSupervisor->CacheRegistersFor(*this);
}

void
TaskInfo::SetName(std::string_view name) noexcept
{
  mThreadName = name;
}

void
TaskInfo::Invalidate() noexcept
{
  mInvalid = true;
  mBreakpointLocationStatus.Clear();
}

void
TaskInfo::SetExited() noexcept
{
  mExited = true;
  Invalidate();
}

void
TaskInfo::ReInit() noexcept
{
  mUnhandledInitPtraceEvent = std::nullopt;
  mResumeRequest = { tc::RunType::Continue, 0 };

  mTraceeState = TraceeState::TraceEventStopped;
  mHasStarted = false;
  mExited = false;
  mReaped = false;
  mKilled = false;
  mRequestedStop = false;
  mRegisterCacheDirty = true;
  // Task is reborn
  mInvalid = false;
  SetInvalidCache();
}

std::string_view
TaskInfo::GetName() const noexcept
{
  return mThreadName;
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

tc::SupervisorState *
TaskInfo::GetSupervisor() const noexcept
{
  return mSupervisor;
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
  SetInvalidCache();
}

void
TaskInfo::SetSignalToForward(int signal) noexcept
{
  DBGLOG(core, "Set signal={} to forward for task={}", signal, mTid);
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
TaskInfo::SetTimestampCreated(u64 time) noexcept
{
  mTimestampCreated = time;
}

void
TaskInfo::StepOverBreakpoint() noexcept
{
  MDB_ASSERT(mBreakpointLocationStatus.IsValid(), "Requires a valid bpstat");

  auto userBreakpointIds = mBreakpointLocationStatus.mBreakpointLocation->GetUserIds();
  DBGBUFLOG(control,
    "Task {} stepping over bps {} at {}",
    mTid,
    JoinFormatIterator{ userBreakpointIds, ", " },
    mBreakpointLocationStatus.mBreakpointLocation->Address());

  mBreakpointLocationStatus.mBreakpointLocation->Disable(mTid, *mSupervisor);
  mBreakpointLocationStatus.mIsSteppingOver = true;
  mSupervisor->DoResumeTask(*this, tc::RunType::Step);
}

void
TaskInfo::SetAtTraceEventStop() noexcept
{
  mTraceeState = TraceeState::TraceEventStopped;
}

void
TaskInfo::SetIsRunning() noexcept
{
  mTraceeState = TraceeState::Running;
  SetInvalidCache();
}

bool
TaskInfo::CanContinue() noexcept
{
  return IsStopped() && !mReaped;
}

void
TaskInfo::SetInvalidCache() noexcept
{
  mRegisterCacheDirty = true;
  mTaskCallstack->SetDirty();
  // Clear the variables reference cache
  for (const auto ref : variableReferences) {
    Tracer::DestroyVariablesReference(ref);
  }

  variableReferences.clear();
  mVariablesCache.clear();
}

void
TaskInfo::AddBreakpointLocationStatus(BreakpointLocation *breakpointLocation) noexcept
{
  MDB_ASSERT(
    !mBreakpointLocationStatus.IsValid(), "Handling a new breakpoint hit without having finalized the last one.");
  mBreakpointLocationStatus.Clear();
  mBreakpointLocationStatus.mBreakpointLocation = RefPtr{ breakpointLocation };
}

void
TaskInfo::ClearBreakpointLocStatus() noexcept
{
  DBGLOG(core, "clearing breakpoint location status");
  mBreakpointLocationStatus.Clear();
}

bool
TaskInfo::IsStopped() const noexcept
{
  return mTraceeState > TraceeState::Running;
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