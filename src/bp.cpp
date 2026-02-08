/** LICENSE TEMPLATE */
#include "bp.h"

// mdb
#include <common/panic.h>
#include <events/stop_event.h>
#include <interface/dap/events.h>
#include <interface/tracee_command/supervisor_state.h>
#include <mdbjs/bpjs.h>
#include <mdbjs/mdbjs.h>
#include <mdbsys/ptrace.h>
#include <symbolication/objfile.h>
#include <task.h>
#include <tracer.h>
#include <utils/logger.h>
#include <utils/todo.h>

// std
#include <algorithm>
#include <type_traits>

#define BP_KEEP(STOP)                                                                                             \
  BreakpointHitEventResult { this, STOP }
#define BP_RETIRE(STOP)                                                                                           \
  BreakpointHitEventResult { this, STOP, BreakpointOp::Retire }
namespace mdb {

BreakpointLocation::BreakpointLocation(AddrPtr address, u8 original) noexcept
    : mAddress(address), mOriginalByte(original)
{
  DBGBUFLOG(control, "[breakpoint loc]: Constructed breakpoint location at {}", address);
}

BreakpointLocation::BreakpointLocation(
  AddrPtr address, u8 original, std::unique_ptr<LocationSourceInfo> sourceLocationInfo) noexcept
    : mAddress(address), mSourceLocation(std::move(sourceLocationInfo)), mOriginalByte(original)
{
  DBGLOG(core, "[breakpoint loc]: Constructed breakpoint location at {}", address);
}

BreakpointLocation::~BreakpointLocation() noexcept
{
  MDB_ASSERT(!mInstalled, "Breakpoint location was enabled while being destroyed - this is a hard error");
  MDB_ASSERT(mUserMapping.empty(),
    "This breakpoint location was destroyed when having active (but destroyed) users registered to it");
  DBGLOG(core, "[breakpoint loc]: Destroying breakpoint location at {}", mAddress);
}

/*static*/ BreakpointLocation::Ref
BreakpointLocation::CreateLocation(AddrPtr address, u8 original) noexcept
{
  return RefPtr<BreakpointLocation>::MakeShared(address, original);
}
/*static*/ BreakpointLocation::Ref
BreakpointLocation::CreateLocationWithSource(
  AddrPtr address, u8 original, std::unique_ptr<LocationSourceInfo> sourceLocationInfo) noexcept
{
  return RefPtr<BreakpointLocation>::MakeShared(address, original, std::move(sourceLocationInfo));
}

bool
BreakpointLocation::AnyUsersActive() const noexcept
{
  return std::any_of(
    mUserMapping.begin(), mUserMapping.end(), [](const auto user) { return user->IsEnabledAndInstalled(); });
}

std::vector<u32>
BreakpointLocation::GetUserIds() const noexcept
{
  std::vector<u32> usr{};
  usr.reserve(mUserMapping.size());
  for (auto *u : mUserMapping) {
    usr.push_back(u->mId);
  }
  return usr;
}

const LocationSourceInfo *
BreakpointLocation::GetSourceLocationInfo() const noexcept
{
  if (mSourceLocation) {
    return mSourceLocation.get();
  }
  return nullptr;
}

bool
BreakpointLocation::RemoveUserOfThis(tc::SupervisorState &controller, UserBreakpoint &breakpoint) noexcept
{
  auto it = std::ranges::find(mUserMapping, &breakpoint);
  if (it == std::end(mUserMapping)) {
    return false;
  }

  mUserMapping.erase(it);
  if (!AnyUsersActive()) {
    Disable(controller.TaskLeaderTid(), controller);
  }
  return true;
}

void
BreakpointLocation::Enable(Tid taskId, tc::SupervisorState &controller) noexcept
{
  if (mUserMapping.empty()) {
    MDB_ASSERT(!mInstalled, "A breakpoint location, with no users, but is installed?");
    DBGLOG(core, "BreakpointLocation has no users.");
    return;
  }

  if (!mInstalled) {
    const auto res = controller.EnableBreakpoint(taskId, *this);
    switch (res.kind) {
    case tc::TaskExecuteResult::Ok:
      mInstalled = true;
      break;
    case tc::TaskExecuteResult::Error:
    case tc::TaskExecuteResult::None:
      break;
    }
  }
}

void
BreakpointLocation::Disable(Tid taskId, tc::SupervisorState &controller) noexcept
{
  if (mInstalled) {
    const auto result = controller.DisableBreakpoint(taskId, *this);
    VERIFY(result.kind == tc::TaskExecuteResult::Ok,
      "[tracer:{}.{}] Failed to disable breakpoint",
      controller.TaskLeaderTid(),
      taskId);
    mInstalled = false;
  }
}

bool
BreakpointLocation::IsInstalled() const noexcept
{
  return mInstalled;
}

void
BreakpointLocation::AddUser(tc::SupervisorState &controller, UserBreakpoint &breakpoint) noexcept
{
  MDB_ASSERT(
    std::none_of(mUserMapping.begin(), mUserMapping.begin(), [&breakpoint](auto v) { return v != &breakpoint; }),
    "Expected user breakpoint to not be registered with bploc");
  mUserMapping.push_back(&breakpoint);

  if (!mInstalled) {
    breakpoint.Enable(controller);
  }
}

UserBreakpoint::UserBreakpoint(RequiredUserParameters param, LocationUserKind locationUserKind) noexcept
    : mId(param.mBreakpointId), mTid(param.mTaskId), mKind(locationUserKind),
      mHitCondition(param.mTimesToHit.value_or(0))
{

  if (param.mBreakpointLocationResult.is_expected()) {
    mBreakpointLocation = std::move(param.mBreakpointLocationResult.take_value());
    mInstallError = nullptr;
  } else {
    mBreakpointLocation = nullptr;
    mInstallError = std::make_unique<BreakpointError>(param.mBreakpointLocationResult.take_error());
  }

  if (mBreakpointLocation != nullptr) {
    mBreakpointLocation->AddUser(param.mControl, *this);
  }
}

UserBreakpoint::~UserBreakpoint() noexcept = default;

BreakpointLocation::Ref
UserBreakpoint::GetLocation() noexcept
{
  return mBreakpointLocation;
}

bool
UserBreakpoint::IsEnabledAndInstalled() noexcept
{
  return mEnabledByUser && mBreakpointLocation != nullptr && mBreakpointLocation->IsInstalled();
}

void
UserBreakpoint::Enable(tc::SupervisorState &controller) noexcept
{
  if (mEnabledByUser && mBreakpointLocation != nullptr) {
    mEnabledByUser = true;
    mBreakpointLocation->Enable(controller.TaskLeaderTid(), controller);
  }
}

void
UserBreakpoint::Disable(tc::SupervisorState &controller) noexcept
{
  if (mEnabledByUser && mBreakpointLocation != nullptr) {
    mEnabledByUser = false;
    if (mBreakpointLocation->AnyUsersActive()) {
      mBreakpointLocation->Disable(controller.TaskLeaderTid(), controller);
    }
  }
}

std::optional<BreakpointHitEventResult>
UserBreakpoint::EvaluateStopCondition(TaskInfo &t) noexcept
{
  if (!mExpression) {
    return {};
  }

  BreakpointHitEventResult result{ this };
  result.mResult = EventResult::Resume;
  if (!mExpression->Run(&result, t)) {
    return result;
  }
  return result;
}

std::optional<AddrPtr>
UserBreakpoint::Address() const noexcept
{
  if (mBreakpointLocation == nullptr) {
    return {};
  }
  return mBreakpointLocation->Address();
}

bool
UserBreakpoint::IsVerified() const noexcept
{
  return mBreakpointLocation != nullptr;
}

std::optional<u32>
UserBreakpoint::Line() const noexcept
{
  if (!mBreakpointLocation) {
    return {};
  }

  if (const auto *src = mBreakpointLocation->GetSourceLocationInfo(); src) {
    return src->mLineNumber;
  }
  return {};
}

std::optional<u32>
UserBreakpoint::Column() const noexcept
{
  if (!mBreakpointLocation) {
    return {};
  }

  if (const auto *src = mBreakpointLocation->GetSourceLocationInfo(); src) {
    return src->mColumnNumber;
  }
  return {};
}

std::optional<std::string_view>
UserBreakpoint::GetSourceFile() const noexcept
{
  if (!mBreakpointLocation) {
    return {};
  }

  if (const auto *src = mBreakpointLocation->GetSourceLocationInfo(); src) {
    return std::optional{ std::string_view{ src->mSourceFile } };
  }
  return {};
}

std::optional<std::pmr::string>
UserBreakpoint::GetErrorMessage(std::pmr::memory_resource *rsrc) const noexcept
{
  return mdb::transform(mInstallError, [t = this, rsrc](const BreakpointError &err) {
    std::pmr::string message{ rsrc };
    auto it = std::back_inserter(message);
    std::visit(
      [t, &it](const auto &e) {
        using T = std::remove_cvref_t<decltype(e)>;
        if constexpr (std::is_same_v<T, MemoryError>) {
          std::format_to(it, "Could not write to {} ({})", e.mRequestedAddress, strerror(e.mErrorNumber));
        } else if constexpr (std::is_same_v<T, ResolveError>) {
          const auto *spec = t->UserProvidedSpec();
          if (spec) {
            std::format_to(it, "Could not resolve using spec: {}", *spec);
          } else {
            std::format_to(it, "Could not resolve breakpoint using spec");
          }
        } else {
          static_assert(always_false<T>, "Should be unreachable");
        }
      },
      err);
    return message;
  });
}

void
UserBreakpoint::UpdateLocation(Ref<BreakpointLocation> breakpointLocation) noexcept
{
  mBreakpointLocation = std::move(breakpointLocation);
}

void
UserBreakpoint::SetExpression(std::unique_ptr<js::JsBreakpointFunction> expression) noexcept
{
  mExpression = std::move(expression);
}

/* virtual */
BreakpointSpecification *
UserBreakpoint::UserProvidedSpec() const noexcept
{
  return nullptr;
}

/* virtual */
Ref<UserBreakpoint>
UserBreakpoint::CloneBreakpoint(
  ProcessBreakpointsManager &breakpointStorage, tc::SupervisorState &tc, Ref<BreakpointLocation> bp) noexcept
{
  IGNORE_ARGS(breakpointStorage, tc, bp);
  PANIC("Generic user breakpoint should not be cloned. This is icky that I've done it like this.");
  return nullptr;
}

Breakpoint::Breakpoint(
  RequiredUserParameters param, LocationUserKind kind, std::unique_ptr<BreakpointSpecification> spec) noexcept
    : UserBreakpoint(std::move(param), kind), mBreakpointSpec(std::move(spec))
{
  if (mBreakpointSpec->mCondition) {
    auto res = js::JsBreakpointFunction::CreateJsBreakpointFunction(
      js::Scripting::Get().GetContext(), *mBreakpointSpec->mCondition);
    if (res.has_value()) {
      SetExpression(std::move(*res));
    }
  }
}

static bool
HookRequestedResume(EventResult result) noexcept
{
  return result == EventResult::Resume;
}

constexpr static BreakpointBehavior
DetermineBehavior(EventResult evaluationResult, tc::SupervisorState &tc) noexcept
{
  MDB_ASSERT(evaluationResult != EventResult::Resume, "Requires a stop behavior (or default)");
  if (evaluationResult == EventResult::Stop) {
    return BreakpointBehavior::StopOnlyThreadThatHit;
  }
  if (evaluationResult == EventResult::StopAll) {
    return BreakpointBehavior::StopAllThreadsWhenHit;
  }
  // Get session-wide configuration of breakpoint behavior.
  return tc.GetBreakpointBehavior();
}

BreakpointHitEventResult
Breakpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  DBGBUFLOG(control, "[{}:bkpt]: bp {} hit", task.mTid, mId);
  IncrementHitCount();

  const auto evaluatedResult = EvaluateStopCondition(task).value_or(BreakpointHitEventResult{ this });

  if (HookRequestedResume(evaluatedResult.mResult)) {
    return evaluatedResult;
  };

  if (DetermineBehavior(evaluatedResult.mResult, controller) == BreakpointBehavior::StopAllThreadsWhenHit) {
    controller.StopAllTasks(
      [&]() { controller.EmitStoppedAtBreakpoints({ .pid = 0, .tid = task.mTid }, mId, true); });
  } else {
    controller.EmitStoppedAtBreakpoints({ .pid = 0, .tid = task.mTid }, mId, false);
  }
  return BP_KEEP(EventResult::Stop);
}

BreakpointSpecification *
Breakpoint::UserProvidedSpec() const noexcept
{
  return mBreakpointSpec.get();
}

Ref<UserBreakpoint>
Breakpoint::CloneBreakpoint(ProcessBreakpointsManager &breakpointStorage,
  tc::SupervisorState &controller,
  Ref<BreakpointLocation> breakpointLocation) noexcept
{

  auto breakpoint = Ref<Breakpoint>::MakeShared(RequiredUserParameters{ .mTaskId = mTid,
                                                  .mBreakpointId = breakpointStorage.NewBreakpointId(),
                                                  .mBreakpointLocationResult = std::move(breakpointLocation),
                                                  .mTimesToHit = {},
                                                  .mControl = controller },
    mKind,
    mBreakpointSpec->Clone());

  breakpointStorage.AddUser(breakpoint);
  MDB_ASSERT(!breakpoint->GetLocation()->GetUserIds().empty(), "Breakpoint location should have user now!");
  return breakpoint;
}

FinishBreakpoint::FinishBreakpoint(RequiredUserParameters param, Tid stopOnlyTaskTid) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::FinishFunction), mStopOnlyTid(stopOnlyTaskTid)
{
}

BreakpointHitEventResult
FinishBreakpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  if (task.mTid != mStopOnlyTid) {
    return BP_KEEP(Resume);
  }
  DBGBUFLOG(control, "Hit finish_bp_t {}", mId);
  const auto all_stopped = controller.IsAllStopped();

  // TODO(simon): This is the point where we should read the value produced by the function we returned from.
  if (all_stopped) {
    controller.EmitSteppedStop({ controller.TaskLeaderTid(), mTid }, "Finished function", true);
  } else {
    controller.StopAllTasks([&controller, tid = mTid]() {
      controller.EmitSteppedStop({ controller.TaskLeaderTid(), tid }, "Finished function", true);
    });
  }
  return BP_RETIRE(Stop);
}

CodeInjectionBoundaryBreakpoint::CodeInjectionBoundaryBreakpoint(RequiredUserParameters param) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::Address)
{
}

BreakpointHitEventResult
CodeInjectionBoundaryBreakpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  DBGBUFLOG(control, "Task {} hit code injection boundary breakpoint at {}", task.mTid, Address().value());
  (void)controller;
  (void)task;
  return BP_KEEP(None);
}

ResumeToBreakpoint::ResumeToBreakpoint(RequiredUserParameters param, Tid tid) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::ResumeTo), mStopOnlyTid(tid)
{
}

BreakpointHitEventResult
ResumeToBreakpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  if (task.mTid == mStopOnlyTid) {
    DBGBUFLOG(control, "Hit resume_bp_t {}", mId);
    return BP_RETIRE(Resume);
  }
  return BP_KEEP(None);
}

Logpoint::Logpoint(RequiredUserParameters param,
  std::string_view logExpression,
  std::unique_ptr<BreakpointSpecification> specification) noexcept
    : Breakpoint(std::move(param), LocationUserKind::LogPoint, std::move(specification))
{
  MDB_ASSERT(!mBreakpointSpec->mCondition, "logpoint should not have condition!");
  prepareExpression(logExpression);
  auto res =
    js::JsBreakpointFunction::CreateJsBreakpointFunction(js::Scripting::Get().GetContext(), mExpressionString);
  // auto res = Tracer::GetScriptingInstance().SourceBreakpointCondition(mId, mExpressionString);
  if (res.has_value()) {
    SetExpression(std::move(*res));
  }
}

void
Logpoint::prepareExpression(std::string_view expr) noexcept
{
  if (!expr.starts_with("return")) {
    mExpressionString.append("return `");
  }
  // we magically guess that we have at most 24 interpolated values. Therefore add space for 24 '$'
  mExpressionString.reserve(expr.size() + 24 + "return"sv.size());
  bool previousWasBracket = false;
  for (auto ch : expr) {
    if (ch == '{') {
      if (previousWasBracket) {
        mExpressionString.push_back('{');
        mExpressionString.push_back('{');
        // an "escaped" interpolation was seen ({{ }} should not be interpreted as ${})
        previousWasBracket = false;
      } else {
        previousWasBracket = true;
      }
    } else {
      if (previousWasBracket) {
        mExpressionString.push_back('$');
        mExpressionString.push_back('{');
        previousWasBracket = false;
      }
      mExpressionString.push_back(ch);
    }
  }
  mExpressionString.push_back('`');
}

void
Logpoint::EvaluateLog(TaskInfo &t) noexcept
{
  if (!mExpression) {
    return;
  }
  TODO("Evaluate the log fn and post a DAP event with the string contents it produced.");
}

BreakpointHitEventResult
Logpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  TODO("Implement this");
  (void)controller;
  (void)task;
  EvaluateLog(task);
  return BP_KEEP(Resume);
}

BreakpointHitEventResult
InternalBreakpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  return mMaintenanceFn();
}

InternalBreakpoint::InternalBreakpoint(RequiredUserParameters param,
  std::string_view debugName,
  std::function<BreakpointHitEventResult()> maintenanceFunc) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::Maintenance), mMaintenanceFn(std::move(maintenanceFunc))
{
}

SOLoadingBreakpoint::SOLoadingBreakpoint(RequiredUserParameters param) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::SharedObjectLoaded)
{
}

BreakpointHitEventResult
SOLoadingBreakpoint::OnHit(tc::SupervisorState &controller, TaskInfo &task) noexcept
{
  controller.OnSharedObjectEvent();
  // we don't stop on shared object loading breakpoints
  return BreakpointHitEventResult{
    .mUserBreakpoint = this, .mResult = EventResult::Resume, .mRetireBreakpoint = BreakpointOp::Keep
  };
}

/* static */
SharedPtr<SessionBreakpoints>
SessionBreakpoints::Create() noexcept
{
  return std::make_shared<SessionBreakpoints>();
}

void
SessionBreakpoints::Clear() noexcept
{
  mUserBreakpoints.clear();
  mUserBreakpointsAtAddress.clear();
  mSourceCodeBreakpoints.clear();
  mFunctionBreakpoints.clear();
  mInstructionBreakpoints.clear();
}

ProcessBreakpointsManager::ProcessBreakpointsManager(tc::SupervisorState &tc) noexcept : mControl(tc) {}

u16
ProcessBreakpointsManager::NewBreakpointId() noexcept
{
  return Tracer::GenerateNewBreakpointId();
}

void
ProcessBreakpointsManager::OnProcessExit() noexcept
{
  for (auto &user : AllUserBreakpoints()) {
    if (user->mBreakpointLocation) {
      // to prevent assertion. UserBreakpoints is the only type allowed to touch ->installed (via
      // friend-mechanism).
      user->mBreakpointLocation->mInstalled = false;
      user->mBreakpointLocation->mUserMapping.clear();
      user->mBreakpointLocation = nullptr;
    }
  }
  mUserBreakpoints.clear();
  mUserBreakpointsAtAddress.clear();
  mSourceCodeBreakpoints.clear();
  mFunctionBreakpoints.clear();
  mInstructionBreakpoints.clear();
}

void
ProcessBreakpointsManager::OnExec() noexcept
{
  for (auto &user : AllUserBreakpoints()) {
    if (user->mBreakpointLocation) {
      // to prevent assertion. UserBreakpoints is the only type allowed to touch ->installed (via
      // friend-mechanism).
      user->mBreakpointLocation->mInstalled = false;
      user->mBreakpointLocation->mUserMapping.clear();
      user->mBreakpointLocation.Reset();
    }
  }
  mUserBreakpointsAtAddress.clear();
}

void
ProcessBreakpointsManager::AddBreakpointLocation(const UserBreakpoint &updatedBreakpoint) noexcept
{
  mUserBreakpointsAtAddress[updatedBreakpoint.Address().value()].push_back(updatedBreakpoint.mId);
}

void
ProcessBreakpointsManager::AddUser(Ref<UserBreakpoint> breakpoint) noexcept
{
  if (breakpoint->IsVerified()) {
    AddBreakpointLocation(*breakpoint);
  }
  mUserBreakpoints[breakpoint->mId] = std::move(breakpoint);
}

void
ProcessBreakpointsManager::RemoveUserBreakpoint(u32 breakpointId) noexcept
{
  auto bp = mUserBreakpoints.find(breakpointId);
  if (bp == std::end(mUserBreakpoints)) {
    return;
  }

  if (bp->second->mBreakpointLocation) {
    bp->second->mBreakpointLocation->RemoveUserOfThis(mControl, *bp->second);
  }

  mUserBreakpoints.erase(bp);
}

Ref<BreakpointLocation>
ProcessBreakpointsManager::GetLocationAt(AddrPtr address) noexcept
{
  auto firstUserBreakpointAt = mUserBreakpointsAtAddress.find(address);
  if (firstUserBreakpointAt == std::end(mUserBreakpointsAtAddress)) {
    return nullptr;
  }
  for (const auto it : firstUserBreakpointAt->second) {
    if (const auto ubp = mUserBreakpoints.find(it); ubp != std::end(mUserBreakpoints)) {
      if (const auto loc = ubp->second->GetLocation(); loc != nullptr) {
        return loc;
      }
    }
  }
  return nullptr;
}

Ref<UserBreakpoint>
ProcessBreakpointsManager::GetUserBreakpoint(u32 id) const noexcept
{
  auto it = mUserBreakpoints.find(id);
  if (it == std::end(mUserBreakpoints)) {
    return nullptr;
  }

  return it->second;
}

std::vector<Ref<UserBreakpoint>>
ProcessBreakpointsManager::AllUserBreakpoints() const noexcept
{
  std::vector<Ref<UserBreakpoint>> result{};
  result.reserve(mUserBreakpoints.size());

  for (auto [id, user] : mUserBreakpoints) {
    result.emplace_back(std::move(user));
  }
  return result;
}

std::vector<Ref<UserBreakpoint>>
ProcessBreakpointsManager::GetNonVerified() const noexcept
{
  std::vector<Ref<UserBreakpoint>> result;
  for (const auto &[id, bp] : mUserBreakpoints) {
    if (!bp->IsVerified()) {
      result.push_back(bp);
    }
  }

  return result;
}

SourceFileBreakpointMap &
ProcessBreakpointsManager::GetBreakpointsFromSourceFile(const SourceCodeFileName &sourceCodeFileName) noexcept
{
  return mSourceCodeBreakpoints[sourceCodeFileName];
}

SourceFileBreakpointMap &
ProcessBreakpointsManager::GetBreakpointsFromSourceFile(std::string_view sourceCodeFileName) noexcept
{
  return mSourceCodeBreakpoints[std::string{ sourceCodeFileName }];
}

std::vector<std::string_view>
ProcessBreakpointsManager::GetSourceFilesWithBreakpointSpecs() const noexcept
{
  std::vector<std::string_view> result{ 15 };
  result.reserve(mSourceCodeBreakpoints.size());
  for (const auto &[source, _] : mSourceCodeBreakpoints) {
    result.emplace_back(std::string_view{ source });
  }
  return result;
}

/* static */
Expected<Ref<BreakpointLocation>, BreakpointError>
ProcessBreakpointsManager::CreateBreakpointLocation(tc::SupervisorState &supervisor, AddrPtr address) noexcept
{
  return supervisor.GetOrCreateBreakpointLocation(address);
}
} // namespace mdb