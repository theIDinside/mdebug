#include "bp.h"
#include "ptrace.h"
#include "utils/expected.h"
#include <algorithm>
#include <supervisor.h>
#include <symbolication/objfile.h>
#include <tracer.h>
#include <type_traits>

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

/*static*/ std::shared_ptr<BreakpointLocation>
BreakpointLocation::CreateLocation(AddrPtr addr, u8 original) noexcept
{
  return std::make_shared<BreakpointLocation>(addr, original);
}
/*static*/ std::shared_ptr<BreakpointLocation>
BreakpointLocation::CreateLocationWithSource(AddrPtr addr, u8 original,
                                             std::unique_ptr<LocationSourceInfo> &&src_info) noexcept
{
  return std::make_shared<BreakpointLocation>(addr, original, std::move(src_info));
}

bool
BreakpointLocation::any_user_active() const noexcept
{
  return std::any_of(users.begin(), users.end(), [](const auto user) { return user->is_enabled(); });
}

std::vector<u32>
BreakpointLocation::loc_users() const noexcept
{
  std::vector<u32> usr{};
  usr.reserve(users.size());
  for (auto u : users) {
    usr.push_back(u->id);
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
    disable(ctrl);
  }
  return true;
}

void
BreakpointLocation::enable(tc::TraceeCommandInterface &tc) noexcept
{
  if (!installed) {
    const auto res = tc.EnableBreakpoint(*this);
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
BreakpointLocation::disable(tc::TraceeCommandInterface &tc) noexcept
{
  if (installed) {
    const auto result = tc.DisableBreakpoint(*this);
    switch (result.kind) {
    case tc::TaskExecuteResult::Ok:
      installed = false;
      break;
    case tc::TaskExecuteResult::Error:
    case tc::TaskExecuteResult::None:
      PANIC("Failed to disable breakpoint");
      break;
    }
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
    user.enable(ctrl);
  }
}

UserBreakpoint::UserBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                               std::optional<StopCondition> &&cond) noexcept
    : enabled_by_user(true), stop_condition(std::move(cond)), id(param.id), tid(param.tid), kind(kind),
      hit_count(param.times_to_hit.value_or(0))
{

  if (param.loc_or_err.is_expected()) {
    bp = std::move(param.loc_or_err.take_value());
    err = nullptr;
  } else {
    bp = nullptr;
    err = std::make_unique<BpErr>(param.loc_or_err.take_error());
  }

  if (bp != nullptr) {
    bp->add_user(param.tc.GetInterface(), *this);
  }
}

UserBreakpoint::~UserBreakpoint() noexcept = default;

void
UserBreakpoint::pre_destruction(tc::TraceeCommandInterface &ctrl) noexcept
{
  if (bp) {
    bp->remove_user(ctrl, *this);
  }
}

void
UserBreakpoint::update_location(std::shared_ptr<BreakpointLocation> bploc) noexcept
{
  bp = std::move(bploc);
}

std::shared_ptr<BreakpointLocation>
UserBreakpoint::bp_location() noexcept
{
  return bp;
}

void
UserBreakpoint::increment_count() noexcept
{
  ++on_hit_count;
}

bool
UserBreakpoint::is_enabled() noexcept
{
  return bp != nullptr && enabled_by_user && bp->is_installed();
}

void
UserBreakpoint::enable(tc::TraceeCommandInterface &ctrl) noexcept
{
  if (!enabled_by_user && bp != nullptr) {
    bp->enable(ctrl);
  }

  enabled_by_user = (bp != nullptr);
}

void
UserBreakpoint::disable(tc::TraceeCommandInterface &ctrl) noexcept
{
  if (enabled_by_user && bp != nullptr) {
    enabled_by_user = false;
    if (bp->any_user_active()) {
      bp->disable(ctrl);
    }
  }
}

Tid
UserBreakpoint::get_tid() noexcept
{
  return tid;
}

bool
UserBreakpoint::check_should_stop(TaskInfo &t) noexcept
{
  return stop_condition.transform([&](auto &fn) { return fn(this, t); }).value_or(true);
}

std::optional<AddrPtr>
UserBreakpoint::address() const noexcept
{
  if (bp == nullptr) {
    return {};
  }
  return bp->address();
}

bool
UserBreakpoint::verified() const noexcept
{
  return bp != nullptr;
}

std::optional<u32>
UserBreakpoint::line() const noexcept
{
  if (!bp) {
    return {};
  }

  if (auto src = bp->get_source(); src) {
    return src->line;
  } else {
    return {};
  }
}

std::optional<u32>
UserBreakpoint::column() const noexcept
{
  if (!bp) {
    return {};
  }

  if (auto src = bp->get_source(); src) {
    return src->column;
  } else {
    return {};
  }
}

std::optional<std::string_view>
UserBreakpoint::source_file() const noexcept
{
  if (!bp) {
    return {};
  }

  if (auto src = bp->get_source(); src) {
    return std::optional{std::string_view{src->source_file}};
  } else {
    return {};
  }
}

std::optional<std::string>
UserBreakpoint::error_message() const noexcept
{
  return utils::transform(err, [t = this](const BpErr &err) {
    std::string message{};
    auto it = std::back_inserter(message);
    std::visit(
      [t, &it](const auto &e) {
        using T = std::remove_cvref_t<decltype(e)>;
        if constexpr (std::is_same_v<T, MemoryError>) {
          fmt::format_to(it, "Could not write to {} ({})", e.requested_address, strerror(e.error_no));
        } else if constexpr (std::is_same_v<T, ResolveError>) {
          auto spec = t->user_spec();
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

UserBpSpec *
UserBreakpoint::user_spec() const noexcept
{
  return nullptr;
}

Breakpoint::Breakpoint(RequiredUserParameters param, LocationUserKind kind, std::optional<Tid> stop_only,
                       std::optional<StopCondition> &&stop_condition, bool stop_all_threads_when_hit,
                       std::unique_ptr<UserBpSpec> &&spec) noexcept
    : UserBreakpoint(std::move(param), kind, std::move(stop_condition)), stop_only(stop_only),
      stop_all_threads_when_hit(stop_all_threads_when_hit), bp_spec(std::move(spec))
{
}

bp_hit
Breakpoint::on_hit(TraceeController &tc, TaskInfo &t) noexcept
{
  if (stop_only.value_or(t.tid) != t.tid) {
    // This task (`TaskInfo t`) is not supposed to be stopped by this breakpoint
    return bp_hit::noop();
  }

  if (!UserBreakpoint::check_should_stop(t)) {
    return bp_hit::noop();
  }

  DBGLOG(core, "Hit breakpoint {}", id);
  increment_count();
  if (stop_all_threads_when_hit) {
    const auto all_stopped = tc.IsAllStopped();
    if (all_stopped) {
      tc.EmitStoppedAtBreakpoints({.pid = 0, .tid = t.tid}, id, true);
    } else {
      tc.StopAllTasks(&t);
      tc.GetPublisher(ObserverType::AllStop).once([&]() {
        tc.EmitStoppedAtBreakpoints({.pid = 0, .tid = t.tid}, id, true);
      });
    }
  } else {
    tc.EmitStoppedAtBreakpoints({.pid = 0, .tid = t.tid}, id, false);
  }
  return bp_hit::normal_stop();
}

UserBpSpec *
Breakpoint::user_spec() const noexcept
{
  return bp_spec.get();
}

TemporaryBreakpoint::TemporaryBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                                         std::optional<Tid> stop_only, std::optional<StopCondition> &&cond,
                                         bool stop_all_threads_when_hit) noexcept
    : Breakpoint(std::move(param), kind, stop_only, std::move(cond), stop_all_threads_when_hit, nullptr)
{
}

bp_hit
TemporaryBreakpoint::on_hit(TraceeController &tc, TaskInfo &t) noexcept
{
  const auto res = Breakpoint::on_hit(tc, t);
  if (res.stop) {
    DBGLOG(core, "Hit temporary_breakpoint_t {}", id);
    return bp_hit::stop_retire_bp();
  } else {
    return bp_hit::noop();
  }
}

FinishBreakpoint::FinishBreakpoint(RequiredUserParameters param, Tid stop_only) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::FinishFunction, std::nullopt), stop_only(stop_only)
{
}

bp_hit
FinishBreakpoint::on_hit(TraceeController &tc, TaskInfo &t) noexcept
{
  if (t.tid != stop_only) {
    return bp_hit::noop();
  }
  DBGLOG(core, "Hit finish_bp_t {}", id);
  const auto all_stopped = tc.IsAllStopped();

  // TODO(simon): This is the point where we should read the value produced by the function we returned from.
  if (all_stopped) {
    tc.EmitSteppedStop({tc.TaskLeaderTid(), tid}, "Finished function", true);
  } else {
    tc.StopAllTasks(&t);
    tc.GetPublisher(ObserverType::AllStop).once([&tc, tid = tid]() {
      tc.EmitSteppedStop({tc.TaskLeaderTid(), tid}, "Finished function", true);
    });
  }
  return bp_hit::stop_retire_bp();
}

ResumeToBreakpoint::ResumeToBreakpoint(RequiredUserParameters param, Tid tid) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::ResumeTo, {}), stop_only(tid)
{
}

bp_hit
ResumeToBreakpoint::on_hit(TraceeController &, TaskInfo &t) noexcept
{
  if (t.tid == stop_only) {
    DBGLOG(core, "Hit resume_bp_t {}", id);
    return bp_hit::continue_retire_bp();
  } else {
    return bp_hit::noop();
  }
}

Logpoint::Logpoint(RequiredUserParameters param, std::string logExpression,
                   std::optional<StopCondition> &&stop_condition, std::unique_ptr<UserBpSpec> &&spec) noexcept
    : Breakpoint(std::move(param), LocationUserKind::LogPoint, std::nullopt, std::move(stop_condition), false,
                 std::move(spec)),
      expressionString(std::move(logExpression))
{
}

void
Logpoint::compile_expression() noexcept
{
  // TODO(simon): Implement some form of rudimentary scripting language here. Or perhaps a DSL strictly for
  // logging. Whatever really.
}

bp_hit
Logpoint::on_hit(TraceeController &, TaskInfo &) noexcept
{
  if (compiledExpression == nullptr) {
    compile_expression();
  }
  return bp_hit::noop();
}

SOLoadingBreakpoint::SOLoadingBreakpoint(RequiredUserParameters param) noexcept
    : UserBreakpoint(std::move(param), LocationUserKind::SharedObjectLoaded, std::nullopt)
{
}

bp_hit
SOLoadingBreakpoint::on_hit(TraceeController &tc, TaskInfo &) noexcept
{
  increment_count();
  tc.OnSharedObjectEvent();
  // we don't stop on shared object loading breakpoints
  return bp_hit::noop();
}

UserBreakpoints::UserBreakpoints(TraceeController &tc) noexcept : tc(tc) {}

u16
UserBreakpoints::new_id() noexcept
{
  return Tracer::Instance->new_breakpoint_id();
}

void
UserBreakpoints::on_exit() noexcept
{
  for (auto &user : all_users()) {
    if (user->bp) {
      // to prevent assertion. UserBreakpoints is the only type allowed to touch ->installed (via
      // friend-mechanism).
      user->bp->installed = false;
      user->bp->users.clear();
      user->bp.reset();
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
  // we do the same as on exit here - at least I think we should.
  on_exit();
}

void
UserBreakpoints::add_bp_location(const UserBreakpoint &updated_bp) noexcept
{
  bps_at_loc[updated_bp.address().value()].push_back(updated_bp.id);
}

void
UserBreakpoints::add_user(std::shared_ptr<UserBreakpoint> user_bp) noexcept
{
  user_breakpoints[user_bp->id] = user_bp;
  if (user_bp->verified()) {
    add_bp_location(*user_bp);
  }
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

std::shared_ptr<BreakpointLocation>
UserBreakpoints::location_at(AddrPtr address) noexcept
{
  auto first_user_bp_at = bps_at_loc.find(address);
  if (first_user_bp_at == std::end(bps_at_loc)) {
    return nullptr;
  }
  for (const auto it : first_user_bp_at->second) {
    if (const auto ubp = user_breakpoints.find(it); ubp != std::end(user_breakpoints)) {
      if (const auto loc = ubp->second->bp_location(); loc != nullptr) {
        return loc;
      }
    }
  }
  return nullptr;
}

std::shared_ptr<UserBreakpoint>
UserBreakpoints::get_user(u32 id) const noexcept
{
  auto it = user_breakpoints.find(id);
  if (it == std::end(user_breakpoints)) {
    return nullptr;
  }

  return it->second;
}

std::vector<std::shared_ptr<UserBreakpoint>>
UserBreakpoints::all_users() const noexcept
{
  std::vector<std::shared_ptr<UserBreakpoint>> result{};
  result.reserve(user_breakpoints.size());

  for (auto [id, user] : user_breakpoints) {
    result.emplace_back(std::move(user));
  }
  return result;
}

std::vector<std::shared_ptr<UserBreakpoint>>
UserBreakpoints::non_verified() const noexcept
{
  std::vector<std::shared_ptr<UserBreakpoint>> result;
  for (const auto &[id, bp] : user_breakpoints) {
    if (!bp->verified()) {
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