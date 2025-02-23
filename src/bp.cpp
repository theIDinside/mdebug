/** LICENSE TEMPLATE */
#include "bp.h"
#include "events/stop_event.h"
#include "interface/dap/events.h"
#include "js/TracingAPI.h"
#include "utils/expected.h"
#include <algorithm>
#include <mdbsys/ptrace.h>
#include <supervisor.h>
#include <symbolication/objfile.h>
#include <tracer.h>
#include <type_traits>

#include <mdbjs/bpjs.h>
#include <mdbjs/mdbjs.h>

#define BP_KEEP(STOP)                                                                                             \
  BreakpointHitEventResult { STOP, BreakpointOp::Keep }
#define BP_RETIRE(STOP)                                                                                           \
  BreakpointHitEventResult { STOP, BreakpointOp::Retire }
namespace mdb {

namespace fmt = ::fmt;

BreakpointLocation::BreakpointLocation(AddrPtr addr, u8 original) noexcept
    : addr(addr), source_info(), original_byte(original)
{
  DBGLOG(core, "[breakpoint loc]: Constructed breakpoint location at {}", addr);
}

BreakpointLocation::BreakpointLocation(AddrPtr addr, u8 original,
                                       std::unique_ptr<LocationSourceInfo> &&src_info) noexcept
    : addr(addr), source_info(std::move(src_info)), original_byte(original)
{
  DBGLOG(core, "[breakpoint loc]: Constructed breakpoint location at {}", addr);
}

BreakpointLocation::~BreakpointLocation() noexcept
{
  ASSERT(!installed, "Breakpoint location was enabled while being destroyed - this is a hard error");
  ASSERT(users.empty(),
         "This breakpoint location was destroyed when having active (but destroyed) users registered to it");
  DBGLOG(core, "[breakpoint loc]: Destroying breakpoint location at {}", addr);
}

/*static*/ BreakpointLocation::Ref
BreakpointLocation::CreateLocation(AddrPtr addr, u8 original) noexcept
{
  return RcHandle<BreakpointLocation>::MakeShared(addr, original);
}
/*static*/ BreakpointLocation::Ref
BreakpointLocation::CreateLocationWithSource(AddrPtr addr, u8 original,
                                             std::unique_ptr<LocationSourceInfo> &&src_info) noexcept
{
  return RcHandle<BreakpointLocation>::MakeShared(addr, original, std::move(src_info));
}

bool
BreakpointLocation::any_user_active() const noexcept
{
  return std::any_of(users.begin(), users.end(), [](const auto user) { return user->IsEnabled(); });
}

std::vector<u32>
BreakpointLocation::loc_users() const noexcept
{
  std::vector<u32> usr{};
  usr.reserve(users.size());
  for (auto u : users) {
    usr.push_back(u->mId);
  }
  return usr;
}

const LocationSourceInfo *
BreakpointLocation::get_source() const noexcept
{
  if (source_info) {
    return source_info.get();
  }
  return nullptr;
}

bool
BreakpointLocation::remove_user(tc::TraceeCommandInterface &ctrl, UserBreakpoint &bp) noexcept
{
  auto it = std::find(users.begin(), users.end(), &bp);
  if (it == std::end(users)) {
    return false;
  }

  users.erase(it);
  if (!any_user_active()) {
    disable(ctrl.TaskLeaderTid(), ctrl);
  }
  return true;
}

void
BreakpointLocation::enable(Tid tid, tc::TraceeCommandInterface &tc) noexcept
{
  if (!installed) {
    const auto res = tc.EnableBreakpoint(tid, *this);
    switch (res.kind) {
    case tc::TaskExecuteResult::Ok:
      installed = true;
      break;
    case tc::TaskExecuteResult::Error:
    case tc::TaskExecuteResult::None:
      break;
    }
  }
}

void
BreakpointLocation::disable(Tid tid, tc::TraceeCommandInterface &tc) noexcept
{
  if (installed) {
    const auto result = tc.DisableBreakpoint(tid, *this);
    VERIFY(result.kind == tc::TaskExecuteResult::Ok, "[tracer:{}.{}] Failed to disable breakpoint",
           tc.TaskLeaderTid(), tid);
    installed = false;
  }
}

bool
BreakpointLocation::is_installed() const noexcept
{
  return installed;
}

void
BreakpointLocation::add_user(tc::TraceeCommandInterface &ctrl, UserBreakpoint &user) noexcept
{
  ASSERT(std::none_of(users.begin(), users.begin(), [&user](auto v) { return v != &user; }),
         "Expected user breakpoint to not be registered with bploc");
  users.push_back(&user);

  if (!installed) {
    user.Enable(ctrl);
  }
}

UserBreakpoint::UserBreakpoint(RequiredUserParameters param, LocationUserKind kind) noexcept
    : mId(param.id), mTid(param.tid), mKind(kind), mHitCondition(param.times_to_hit.value_or(0))
{

  if (param.loc_or_err.is_expected()) {
    mBreakpointLocation = std::move(param.loc_or_err.take_value());
    mInstallError = nullptr;
  } else {
    mBreakpointLocation = nullptr;
    mInstallError = std::make_unique<BpErr>(param.loc_or_err.take_error());
  }

  if (mBreakpointLocation != nullptr) {
    mBreakpointLocation->add_user(param.tc.GetInterface(), *this);
  }
}

UserBreakpoint::~UserBreakpoint() noexcept = default;

void
UserBreakpoint::pre_destruction(tc::TraceeCommandInterface &ctrl) noexcept
{
  if (mBreakpointLocation) {
    mBreakpointLocation->remove_user(ctrl, *this);
  }
}

BreakpointLocation::Ref
UserBreakpoint::GetLocation() noexcept
{
  return mBreakpointLocation;
}

bool
UserBreakpoint::IsEnabled() noexcept
{
  return mEnabledByUser && mBreakpointLocation != nullptr && mBreakpointLocation->is_installed();
}

void
UserBreakpoint::Enable(tc::TraceeCommandInterface &ctrl) noexcept
{
  if (mEnabledByUser && mBreakpointLocation != nullptr) {
    mBreakpointLocation->enable(ctrl.TaskLeaderTid(), ctrl);
  }
  mEnabledByUser = mBreakpointLocation != nullptr;
}

void
UserBreakpoint::Disable(tc::TraceeCommandInterface &ctrl) noexcept
{
  if (mEnabledByUser && mBreakpointLocation != nullptr) {
    mEnabledByUser = false;
    if (mBreakpointLocation->any_user_active()) {
      mBreakpointLocation->disable(ctrl.TaskLeaderTid(), ctrl);
    }
  }
}

Tid
UserBreakpoint::GetTid() noexcept
{
  return mTid;
}

EventResult
UserBreakpoint::EvaluateStopCondition(TaskInfo &t) noexcept
{
  if (!mExpression) {
    return EventResult::None;
  }

  return mExpression->EvaluateCondition(Tracer::GetJsContext(), &t, this).value_or(EventResult::None);
}

std::optional<AddrPtr>
UserBreakpoint::Address() const noexcept
{
  if (mBreakpointLocation == nullptr) {
    return {};
  }
  return mBreakpointLocation->address();
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

  if (auto src = mBreakpointLocation->get_source(); src) {
    return src->line;
  } else {
    return {};
  }
}

std::optional<u32>
UserBreakpoint::Column() const noexcept
{
  if (!mBreakpointLocation) {
    return {};
  }

  if (auto src = mBreakpointLocation->get_source(); src) {
    return src->column;
  } else {
    return {};
  }
}

std::optional<std::string_view>
UserBreakpoint::GetSourceFile() const noexcept
{
  if (!mBreakpointLocation) {
    return {};
  }

  if (auto src = mBreakpointLocation->get_source(); src) {
    return std::optional{std::string_view{src->source_file}};
  } else {
    return {};
  }
}

std::optional<std::string>
UserBreakpoint::GetErrorMessage() const noexcept
{
  return mdb::transform(mInstallError, [t = this](const BpErr &err) {
    std::string message{};
    auto it = std::back_inserter(message);
    std::visit(
      [t, &it](const auto &e) {
        using T = std::remove_cvref_t<decltype(e)>;
        if constexpr (std::is_same_v<T, MemoryError>) {
          fmt::format_to(it, "Could not write to {} ({})", e.requested_address, strerror(e.error_no));
        } else if constexpr (std::is_same_v<T, ResolveError>) {
          auto spec = t->UserProvidedSpec();
          if (spec) {
            fmt::format_to(it, "Could not resolve using spec: {}", *spec);
          } else {
            fmt::format_to(it, "Could not resolve breakpoint using spec");
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
UserBreakpoint::UpdateLocation(Ref<BreakpointLocation> bploc) noexcept
{
  mBreakpointLocation = std::move(bploc);
}

void
UserBreakpoint::SetExpression(std::unique_ptr<js::CompileBreakpointCallable> expression) noexcept
{
  mExpression = std::move(expression);
}

void
UserBreakpoint::TraceJs(JSTracer *trace) noexcept
{
  if (mExpression) {
    mExpression->trace(trace, "breakpoint condition");
  }
}

/* virtual */
BreakpointSpecification *
UserBreakpoint::UserProvidedSpec() const noexcept
{
  return nullptr;
}

/* virtual */
Ref<UserBreakpoint>
UserBreakpoint::CloneBreakpoint(UserBreakpoints &breakpointStorage, TraceeController &tc,
                                Ref<BreakpointLocation>) noexcept
{
  PANIC("Generic user breakpoint should not be cloned. This is icky that I've done it like this.");
  return nullptr;
}

Breakpoint::Breakpoint(RequiredUserParameters param, LocationUserKind kind,
                       std::unique_ptr<BreakpointSpecification> spec) noexcept
    : UserBreakpoint(std::move(param), kind), mBreakpointSpec(std::move(spec))
{
  if (mBreakpointSpec->mCondition) {
    auto res = Tracer::GetScriptingInstance().SourceBreakpointCondition(mId, *mBreakpointSpec->mCondition);
    if (res.is_error()) {
      DBGLOG(core, "failed to source breakpoint condition: {}", res.error());
    }
    SetExpression(std::make_unique<js::CompileBreakpointCallable>(JS::Heap{res.value()}));
  }
}

static bool
HookRequestedResume(EventResult result) noexcept
{
  return result == EventResult::Resume;
}

constexpr static BreakpointBehavior
DetermineBehavior(EventResult evaluationResult, TraceeController &tc) noexcept
{
  ASSERT(evaluationResult != EventResult::Resume, "Requires a stop behavior (or default)");
  if (evaluationResult == EventResult::Stop) {
    return BreakpointBehavior::StopOnlyThreadThatHit;
  } else if (evaluationResult == EventResult::StopAll) {
    return BreakpointBehavior::StopAllThreadsWhenHit;
  }
  // Get session-wide configuration of breakpoint behavior.
  return tc.GetBreakpointBehavior();
}

BreakpointHitEventResult
Breakpoint::OnHit(TraceeController &tc, TaskInfo &t) noexcept
{
  DBGLOG(core, "[{}:bkpt]: bp {} hit", t.mTid, mId);
  IncrementHitCount();

  const auto evaluatedResult = EvaluateStopCondition(t);

  if (HookRequestedResume(evaluatedResult)) {
    return BP_KEEP(evaluatedResult);
  };

  if (DetermineBehavior(evaluatedResult, tc) == BreakpointBehavior::StopAllThreadsWhenHit) {
    const auto all_stopped = tc.IsAllStopped();
    if (all_stopped) {
      tc.EmitStoppedAtBreakpoints({.pid = 0, .tid = t.mTid}, mId, true);
    } else {
      tc.StopAllTasks(&t);
      tc.GetPublisher(ObserverType::AllStop).Once([&]() {
        tc.EmitStoppedAtBreakpoints({.pid = 0, .tid = t.mTid}, mId, true);
      });
    }
  } else {
    tc.EmitStoppedAtBreakpoints({.pid = 0, .tid = t.mTid}, mId, false);
  }
  return BP_KEEP(EventResult::Stop);
}

BreakpointSpecification *
Breakpoint::UserProvidedSpec() const noexcept
{
  return mBreakpointSpec.get();
}

Ref<UserBreakpoint>
Breakpoint::CloneBreakpoint(UserBreakpoints &breakpointStorage, TraceeController &tc,
                            Ref<BreakpointLocation> bp) noexcept
{
  auto breakpoint = Ref<Breakpoint>::MakeShared(
    RequiredUserParameters{
      .tid = mTid, .id = breakpointStorage.new_id(), .loc_or_err = std::move(bp), .times_to_hit = {}, .tc = tc},
    mKind, mBreakpointSpec->Clone());

  breakpointStorage.add_user(breakpoint);
  ASSERT(!breakpoint->GetLocation()->loc_users().empty(), "Breakpoint location should have user now!");
  return breakpoint;
}

TemporaryBreakpoint::TemporaryBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                                         std::optional<Tid> stop_only,
                                         std::unique_ptr<js::CompileBreakpointCallable> cond) noexcept
    : Breakpoint(std::move(param), kind, nullptr)
{
}

BreakpointHitEventResult
TemporaryBreakpoint::OnHit(TraceeController &tc, TaskInfo &t) noexcept
{
  const auto res = Breakpoint::OnHit(tc, t);
  if (res.ShouldStop()) {
    DBGLOG(core, "Hit temporary_breakpoint_t {}", mId);
    return BP_RETIRE(res.mResult);
  } else {
    return BP_KEEP(None);
  }
}

FinishBreakpoint::FinishBreakpoint(RequiredUserParameters param, Tid stop_only) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::FinishFunction), stop_only(stop_only)
{
}

BreakpointHitEventResult
FinishBreakpoint::OnHit(TraceeController &tc, TaskInfo &t) noexcept
{
  if (t.mTid != stop_only) {
    return BP_KEEP(Resume);
  }
  DBGLOG(core, "Hit finish_bp_t {}", mId);
  const auto all_stopped = tc.IsAllStopped();

  // TODO(simon): This is the point where we should read the value produced by the function we returned from.
  if (all_stopped) {
    tc.EmitSteppedStop({tc.TaskLeaderTid(), mTid}, "Finished function", true);
  } else {
    tc.StopAllTasks(&t);
    tc.GetPublisher(ObserverType::AllStop).Once([&tc, tid = mTid]() {
      tc.EmitSteppedStop({tc.TaskLeaderTid(), tid}, "Finished function", true);
    });
  }
  return BP_RETIRE(Stop);
}

ResumeToBreakpoint::ResumeToBreakpoint(RequiredUserParameters param, Tid tid) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::ResumeTo), stop_only(tid)
{
}

BreakpointHitEventResult
ResumeToBreakpoint::OnHit(TraceeController &, TaskInfo &t) noexcept
{
  if (t.mTid == stop_only) {
    DBGLOG(core, "Hit resume_bp_t {}", mId);
    return BP_RETIRE(Resume);
  } else {
    return BP_KEEP(None);
  }
}

Logpoint::Logpoint(RequiredUserParameters param, std::string_view logExpression,
                   std::unique_ptr<BreakpointSpecification> spec) noexcept
    : Breakpoint(std::move(param), LocationUserKind::LogPoint, std::move(spec))
{
  ASSERT(!mBreakpointSpec->mCondition, "logpoint should not have condition!");
  prepareExpression(logExpression);
  auto res = Tracer::GetScriptingInstance().SourceBreakpointCondition(mId, mExpressionString);
  if (res.is_error()) {
    DBGLOG(core, "failed to source breakpoint condition: {}", res.error());
  } else {
    SetExpression(std::make_unique<js::CompileBreakpointCallable>(JS::Heap{res.value()}));
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
  auto result = mExpression->EvaluateLog(Tracer::GetJsContext(), &t, this);
  t.GetSupervisor()->GetDebugAdapterProtocolClient()->PostDapEvent(
    new ui::dap::OutputEvent{t.GetSupervisor()->TaskLeaderTid(), "console", std::move(result.value())});
}

BreakpointHitEventResult
Logpoint::OnHit(TraceeController &tc, TaskInfo &t) noexcept
{
  EvaluateLog(t);
  return BP_KEEP(Resume);
}

SOLoadingBreakpoint::SOLoadingBreakpoint(RequiredUserParameters param) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::SharedObjectLoaded)
{
}

BreakpointHitEventResult
SOLoadingBreakpoint::OnHit(TraceeController &tc, TaskInfo &) noexcept
{
  tc.OnSharedObjectEvent();
  // we don't stop on shared object loading breakpoints
  return BreakpointHitEventResult{EventResult::Resume, BreakpointOp::Keep};
}

UserBreakpoints::UserBreakpoints(TraceeController &tc) noexcept : tc(tc)
{
  Tracer::GetScriptingInstance().AddTrace([this](JSTracer *trc) {
    DBGLOG(interpreter, "[GC]: tracing UserBreakpoints::UserBreakpoints");
    for (const auto &user : AllUserBreakpoints()) {
      user->TraceJs(trc);
    }
  });
}

u16
UserBreakpoints::new_id() noexcept
{
  return Tracer::Get().GenerateNewBreakpointId();
}

void
UserBreakpoints::OnProcessExit() noexcept
{
  for (auto &user : AllUserBreakpoints()) {
    if (user->mBreakpointLocation) {
      // to prevent assertion. UserBreakpoints is the only type allowed to touch ->installed (via
      // friend-mechanism).
      user->mBreakpointLocation->installed = false;
      user->mBreakpointLocation->users.clear();
      user->mBreakpointLocation = nullptr;
    }
  }
  user_breakpoints.clear();
  bps_at_loc.clear();
  source_breakpoints.clear();
  fn_breakpoints.clear();
  instruction_breakpoints.clear();
}

void
UserBreakpoints::on_exec() noexcept
{
  for (auto &user : AllUserBreakpoints()) {
    if (user->mBreakpointLocation) {
      // to prevent assertion. UserBreakpoints is the only type allowed to touch ->installed (via
      // friend-mechanism).
      user->mBreakpointLocation->installed = false;
      user->mBreakpointLocation->users.clear();
      user->mBreakpointLocation.Reset();
    }
  }
  bps_at_loc.clear();
}

void
UserBreakpoints::add_bp_location(const UserBreakpoint &updated_bp) noexcept
{
  bps_at_loc[updated_bp.Address().value()].push_back(updated_bp.mId);
}

void
UserBreakpoints::add_user(Ref<UserBreakpoint> user_bp) noexcept
{
  if (user_bp->IsVerified()) {
    add_bp_location(*user_bp);
  }
  user_breakpoints[user_bp->mId] = std::move(user_bp);
}

void
UserBreakpoints::remove_bp(u32 id) noexcept
{
  auto bp = user_breakpoints.find(id);
  if (bp == std::end(user_breakpoints)) {
    return;
  }

  bp->second->pre_destruction(tc.GetInterface());
  user_breakpoints.erase(bp);
}

Ref<BreakpointLocation>
UserBreakpoints::location_at(AddrPtr address) noexcept
{
  auto first_user_bp_at = bps_at_loc.find(address);
  if (first_user_bp_at == std::end(bps_at_loc)) {
    return nullptr;
  }
  for (const auto it : first_user_bp_at->second) {
    if (const auto ubp = user_breakpoints.find(it); ubp != std::end(user_breakpoints)) {
      if (const auto loc = ubp->second->GetLocation(); loc != nullptr) {
        return loc;
      }
    }
  }
  return nullptr;
}

Ref<UserBreakpoint>
UserBreakpoints::GetUserBreakpoint(u32 id) const noexcept
{
  auto it = user_breakpoints.find(id);
  if (it == std::end(user_breakpoints)) {
    return nullptr;
  }

  return it->second;
}

std::vector<Ref<UserBreakpoint>>
UserBreakpoints::AllUserBreakpoints() const noexcept
{
  std::vector<Ref<UserBreakpoint>> result{};
  result.reserve(user_breakpoints.size());

  for (auto [id, user] : user_breakpoints) {
    result.emplace_back(std::move(user));
  }
  return result;
}

std::vector<Ref<UserBreakpoint>>
UserBreakpoints::non_verified() const noexcept
{
  std::vector<Ref<UserBreakpoint>> result;
  for (const auto &[id, bp] : user_breakpoints) {
    if (!bp->IsVerified()) {
      result.push_back(bp);
    }
  }

  return result;
}

UserBreakpoints::SourceFileBreakpointMap &
UserBreakpoints::bps_for_source(const SourceCodeFileName &src_file) noexcept
{
  return source_breakpoints[src_file];
}

UserBreakpoints::SourceFileBreakpointMap &
UserBreakpoints::bps_for_source(std::string_view src_file) noexcept
{
  return source_breakpoints[std::string{src_file}];
}

std::vector<std::string_view>
UserBreakpoints::sources_with_bpspecs() const noexcept
{
  std::vector<std::string_view> result;
  result.reserve(source_breakpoints.size());
  for (const auto &[source, _] : source_breakpoints) {
    result.emplace_back(std::string_view{source});
  }
  return result;
}
} // namespace mdb