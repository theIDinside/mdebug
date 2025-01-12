#include "task.h"
#include "fmt/ranges.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "register_description.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "utils/logger.h"
#include "utils/util.h"
#include <mdbsys/ptrace.h>
#include <sys/user.h>
#include <tracee/util.h>
#include <tracer.h>
#include <utility>

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
    return ::get_register(registers, regNumber);
  case TargetFormat::Remote:
    static_assert(utils::castenum(ArchType::COUNT) == 1, "Supported architectures have increased");
    return registerFile->GetRegister(regNumber);
    break;
  }
  NEVER("Unknown target format");
}

TaskInfo::TaskInfo(pid_t newTaskTid) noexcept
    : mTid(newTaskTid), mLastWaitStatus(), user_stopped(true), tracer_stopped(true), initialized(false),
      cache_dirty(true), rip_dirty(true), exited(false), reaped(false), regs(), loc_stat(), call_stack(nullptr),
      mSupervisor(nullptr)
{
}

TaskInfo::TaskInfo(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isUserStopped) noexcept
    : mTid(newTaskTid), mLastWaitStatus(), user_stopped(isUserStopped), tracer_stopped(true), initialized(true),
      cache_dirty(true), rip_dirty(true), exited(false), reaped(false),
      regs(supervisor.format, supervisor.arch_info.as_t().get()), loc_stat(),
      mSupervisor(supervisor.GetSupervisor())
{
  call_stack = std::make_unique<sym::CallStack>(supervisor.GetSupervisor(), this);
}

void
TaskInfo::InitializeThread(tc::TraceeCommandInterface &tc, bool restart) noexcept
{
  ASSERT(call_stack == nullptr && initialized == false, "Thread has already been initialized.");
  user_stopped = true;
  tracer_stopped = true;
  initialized = true;
  cache_dirty = true;
  rip_dirty = true;
  exited = false;
  reaped = false;
  regs = {tc.format, tc.arch_info.as_t().get()};
  loc_stat = {};
  call_stack = std::make_unique<sym::CallStack>(tc.GetSupervisor(), this);
  mSupervisor = tc.GetSupervisor();
  ASSERT(mSupervisor != nullptr, "must have supervisor");
  DBGLOG(core, "Deferred initializing of thread {} completed", mTid);
  if (restart) {
    EventSystem::Get().PushDebuggerEvent(TraceEvent::ThreadCreated(
      {tc.TaskLeaderTid(), mTid, 5}, {tc::RunType::Continue, tc::ResumeTarget::Task}, {}));
  }
}

/*static*/
std::shared_ptr<TaskInfo>
TaskInfo::CreateTask(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isRunning) noexcept
{
  DBGLOG(core, "creating task {}.{}: running={}", supervisor.TaskLeaderTid(), newTaskTid, isRunning);
  return std::make_shared<TaskInfo>(supervisor, newTaskTid, !isRunning);
}

/** static */
std::shared_ptr<TaskInfo>
TaskInfo::CreateUnInitializedTask(TaskWaitResult wait) noexcept
{
  auto task = std::shared_ptr<TaskInfo>(new TaskInfo{wait.tid});
  Tracer::Instance->RegisterTracedTask(task);
  task->mLastWaitStatus = wait.ws;
  return task;
}

user_regs_struct *
TaskInfo::native_registers() const noexcept
{
  ASSERT(regs.mRegisterFormat == TargetFormat::Native, "Used in the wrong context");
  return regs.registers;
}

RegisterDescription *
TaskInfo::remote_x86_registers() const noexcept
{
  ASSERT(regs.mRegisterFormat == TargetFormat::Remote, "Used in the wrong context");
  return regs.registerFile;
}

void
TaskInfo::remote_from_hexdigit_encoding(std::string_view hex_encoded) noexcept
{
  ASSERT(regs.mRegisterFormat == TargetFormat::Remote, "Expected remote format");

  regs.registerFile->FillFromHexEncodedString(hex_encoded);
  set_updated();
}

const TaskRegisters &
TaskInfo::GetRegisterCache() const
{
  return regs;
}

u64
TaskInfo::get_register(u64 reg_num) noexcept
{
  return regs.GetRegister(reg_num);
}

u64
TaskInfo::unwind_buffer_register(u8 level, u16 register_number) const noexcept
{
  return call_stack->UnwindRegister(level, register_number);
}

void
TaskInfo::StoreToRegisterCache(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept
{
  regs.registerFile->Store(data);
}

#define RETURN_RET_ADDR_IF(cond)                                                                                  \
  if ((cond))                                                                                                     \
    return call_stack->ReturnAddresses();

#define RETURN_RET_ADDR_LOG(cond, ...)                                                                            \
  if ((cond)) {                                                                                                   \
    DBGLOG(core, __VA_ARGS__);                                                                                    \
    return call_stack->ReturnAddresses();                                                                         \
  }

std::span<const AddrPtr>
TaskInfo::return_addresses(TraceeController *tc, CallStackRequest req) noexcept
{
  RETURN_RET_ADDR_IF(!call_stack->IsDirty());

  tc->CacheRegistersFor(*this);
  // initialize bottom frame's registers with actual live register contents
  // this is then used to execute the dwarf binary code
  call_stack->Unwind(req);
  return call_stack->ReturnAddresses();
}

sym::FrameUnwindState *
TaskInfo::GetUnwindState(int frameLevel) noexcept
{
  return call_stack->GetUnwindState(static_cast<u32>(frameLevel));
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
TaskInfo::pending_wait_status() const noexcept
{
  ASSERT(mLastWaitStatus.ws != WaitStatusKind::NotKnown, "Wait status unknown for {}", mTid);
  return mLastWaitStatus;
}

sym::CallStack &
TaskInfo::get_callstack() noexcept
{
  return *call_stack;
}

void
TaskInfo::clear_stop_state() noexcept
{
  for (const auto ref : variableReferences) {
    Tracer::Instance->destroy_reference(ref);
  }

  variableReferences.clear();
  valobj_cache.clear();
}

void
TaskInfo::add_reference(u32 id) noexcept
{
  variableReferences.push_back(id);
}

void
TaskInfo::cache_object(u32 ref, SharedPtr<sym::Value> value) noexcept
{
  valobj_cache.emplace(ref, std::move(value));
}

SharedPtr<sym::Value>
TaskInfo::get_maybe_value(u32 ref) noexcept
{
  auto it = valobj_cache.find(ref);
  if (it == std::end(valobj_cache)) {
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

void TaskInfo::SetTracerState(SupervisorState state) noexcept {
  mState = state;
}

void
TaskInfo::step_over_breakpoint(TraceeController *tc, tc::ResumeAction resume) noexcept
{
  ASSERT(loc_stat.has_value(), "Requires a valid bpstat");

  auto loc = tc->GetUserBreakpoints().location_at(loc_stat->loc);
  auto user_ids = loc->loc_users();
  DBGLOG(core, "[TaskInfo {}] Stepping over bps {} at {}", mTid, fmt::join(user_ids, ", "), loc->address());

  auto &control = tc->GetInterface();
  loc->disable(mTid, control);
  loc_stat->stepped_over = true;
  loc_stat->re_enable_bp = true;
  loc_stat->should_resume = resume.type != tc::RunType::None;

  mNextResumeAction = resume;

  const auto result = control.ResumeTask(*this, tc::ResumeAction{tc::RunType::Step, resume.target, 0});
  ASSERT(result.is_ok(), "Failed to step over breakpoint");
}

void
TaskInfo::set_stop() noexcept
{
  user_stopped = true;
  tracer_stopped = true;
}

void
TaskInfo::SetCurrentResumeAction(tc::ResumeAction type) noexcept
{
  stop_collected = false;
  user_stopped = false;
  tracer_stopped = false;
  mLastResumeAction = type;
  set_dirty();
  clear_stop_state();
}

bool
TaskInfo::can_continue() noexcept
{
  return initialized && (user_stopped || tracer_stopped) && !reaped;
}

void
TaskInfo::set_dirty() noexcept
{
  cache_dirty = true;
  rip_dirty = true;
  call_stack->SetDirty();
}

void
TaskInfo::set_updated() noexcept
{
  rip_dirty = false;
  cache_dirty = false;
}

void
TaskInfo::add_bpstat(AddrPtr address) noexcept
{
  loc_stat = LocationStatus{.loc = address, .should_resume = false, .stepped_over = false, .re_enable_bp = false};
}

std::optional<LocationStatus>
TaskInfo::clear_bpstat() noexcept
{
  const auto copy = loc_stat;
  loc_stat = std::nullopt;
  return copy;
}

bool
TaskInfo::is_stopped() const noexcept
{
  return user_stopped;
}

bool
TaskInfo::stop_processed() const noexcept
{
  return stop_collected;
}

void
TaskInfo::collect_stop() noexcept
{
  stop_collected = true;
  tracer_stopped = true;
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