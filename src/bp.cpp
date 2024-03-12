#include "bp.h"
#include "events/event.h"
#include "ptrace.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/name_index.h"
#include <algorithm>
#include <supervisor.h>
#include <symbolication/objfile.h>

BreakpointLocation::BreakpointLocation(AddrPtr addr, u8 original) noexcept
    : addr(addr), original_byte(original), source_info()
{
  DLOG("mdb", "[breakpoint loc]: Constructed breakpoint location at {}", addr);
}

BreakpointLocation::BreakpointLocation(AddrPtr addr, u8 original,
                                       std::unique_ptr<LocationSourceInfo> &&src_info) noexcept
    : addr(addr), original_byte(original), source_info(std::move(src_info))
{
  DLOG("mdb", "[breakpoint loc]: Constructed breakpoint location at {}", addr);
}

BreakpointLocation::~BreakpointLocation() noexcept
{
  ASSERT(!installed, "Breakpoint location was enabled while being destroyed - this is a hard error");
  DLOG("mdb", "[breakpoint loc]: Destroying breakpoint location at {}", addr);
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
  return std::any_of(users.begin(), users.end(), [](auto user) { return user->is_enabled(); });
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

bool
BreakpointLocation::remove_user(NonNullPtr<UserBreakpoint> bp) noexcept
{
  auto it = std::find(users.begin(), users.end(), bp.ptr);
  if (it == std::end(users))
    return false;

  users.erase(it);
  if (!any_user_active()) {
    disable(bp->get_tid());
  }
  return true;
}

void
BreakpointLocation::enable(Tid tid) noexcept
{
  if (!installed) {
    DLOG("mdb", "[bkpt]: enabling breakpoint at {} (tid: {})", addr, tid);
    constexpr u64 bkpt = 0xcc;
    const auto read_value = ptrace(PTRACE_PEEKDATA, tid, addr.get(), nullptr);
    const u64 installed_bp = ((read_value & ~0xff) | bkpt);
    ptrace(PTRACE_POKEDATA, tid, addr.get(), installed_bp);
    installed = true;
  }
}

void
BreakpointLocation::disable(Tid tid) noexcept
{
  if (installed) {
    DLOG("mdb", "[bkpt]: disabling breakpoint at {} (tid: {})", addr, tid);
    const auto read_value = ptrace(PTRACE_PEEKDATA, tid, addr.get(), nullptr);
    const u64 restore = ((read_value & ~0xff) | original_byte);
    ptrace(PTRACE_POKEDATA, tid, addr.get(), restore);
    installed = false;
  }
}

void
BreakpointLocation::add_user(UserBreakpoint &user) noexcept
{
  ASSERT(std::none_of(users.begin(), users.begin(), [&user](auto v) { return v != &user; }),
         "Expected user breakpoint to not be registered with bploc");
  users.push_back(&user);

  if (!installed) {
    user.enable();
  }
}

UserBreakpoint::UserBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                               std::optional<StopCondition> &&cond) noexcept
    : enabled(true), bp(std::move(param.loc)), stop_condition(std::move(cond)), id(param.id), tid(param.tid),
      kind(kind), hit_count(param.times_to_hit.value_or(0))
{
  if (bp) {
    bp->add_user(*this);
  } else {
    objfile_subscriber = &param.tc.new_objectfile;
  }
}

UserBreakpoint::~UserBreakpoint() noexcept
{
  remove_location();
  if (objfile_subscriber) {
    objfile_subscriber->unsubscribe(SubscriberIdentity::Of(this));
  }
}

void
UserBreakpoint::update_location(std::shared_ptr<BreakpointLocation> bploc) noexcept
{
  bp = std::move(bploc);
}

void
UserBreakpoint::remove_location() noexcept
{
  if (bp) {
    bp->remove_user(NonNullPtr<UserBreakpoint>{this});
    bp = nullptr;
  }
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
  return bp != nullptr && enabled;
}

void
UserBreakpoint::enable() noexcept
{
  if (!enabled && bp != nullptr) {
    bp->enable(tid);
  }

  enabled = (bp != nullptr);
}

void
UserBreakpoint::disable() noexcept
{
  if (enabled && bp != nullptr) {
    bp->disable(tid);
  }
  enabled = false;
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

  if (!bp->source_info) {
    return {};
  }

  return bp->source_info->line;
}

std::optional<u32>
UserBreakpoint::column() const noexcept
{
  if (!bp) {
    return {};
  }

  if (!bp->source_info) {
    return {};
  }

  return bp->source_info->column;
}

std::optional<std::string_view>
UserBreakpoint::source_file() const noexcept
{
  if (!bp) {
    return {};
  }

  if (!bp->source_info) {
    return {};
  }

  return std::optional{std::string_view{bp->source_info->source_file}};
}

Breakpoint::Breakpoint(RequiredUserParameters param, LocationUserKind kind, std::optional<Tid> stop_only,
                       std::optional<StopCondition> &&stop_condition, bool stop_all_threads_when_hit,
                       std::unique_ptr<UserBpSpec> &&spec) noexcept
    : UserBreakpoint(param, kind, std::move(stop_condition)), stop_only(stop_only),
      stop_all_threads_when_hit(stop_all_threads_when_hit), bp_spec(std::move(spec))
{
  static constexpr auto SOURCE_BREAKPOINT = 0;
  static constexpr auto FUNCTION_BREAKPOINT = 1;
  static constexpr auto INSTRUCTION_BREAKPOINT = 2;

  if (!verified()) {
    objfile_subscriber->subscribe(SubscriberIdentity::Of(this), [this, &tc = param.tc](SymbolFile *symbol_file) {
      if (this->bp_spec != nullptr) {
        auto objfile = symbol_file->objectFile();
        switch (this->bp_spec->index()) {
        case SOURCE_BREAKPOINT: {
          const auto &spec = std::get<std::pair<std::string, SourceBreakpointSpec>>(*this->bp_spec);
          if (auto source_code_file = objfile->get_source_file(spec.first); source_code_file) {
            if (auto lte = source_code_file->first_linetable_entry(symbol_file->baseAddress, spec.second.line,
                                                                   spec.second.column);
                lte) {
              const auto pc = lte->pc;
              this->update_location(tc.get_or_create_bp_location(pc, symbol_file->baseAddress, *source_code_file));
              tc.pbps.add_bp_location(this);
              tc.emit_breakpoint_event("changed", *this, std::optional<std::string>{});
              return RemoveSubscriber();
            }
          }
        } break;
        case FUNCTION_BREAKPOINT: {
          const auto &spec = std::get<FunctionBreakpointSpec>(*this->bp_spec);
          auto result = symbol_file->lookup_by_spec(spec);

          if (auto it = std::find_if(result.begin(), result.end(),
                                     [](const auto &it) { return it.loc_src_info.has_value(); });
              it != end(result)) {
            this->update_location(tc.get_or_create_bp_location(it->address, std::move(it->loc_src_info.value())));
            tc.pbps.add_bp_location(this);
            tc.emit_breakpoint_event("changed", *this, std::optional<std::string>{});
            return RemoveSubscriber();
          } else {
            for (auto &&lookup : result) {
              this->update_location(tc.get_or_create_bp_location(lookup.address, false));
              tc.pbps.add_bp_location(this);
              tc.emit_breakpoint_event("changed", *this, std::optional<std::string>{});
              return RemoveSubscriber();
            }
          }
        } break;
        case INSTRUCTION_BREAKPOINT:
          const auto &spec = std::get<InstructionBreakpointSpec>(*this->bp_spec);
          auto addr_opt = to_addr(spec.instructionReference);
          ASSERT(addr_opt.has_value(), "Failed to convert instructionReference to valid address");
          const auto addr = addr_opt.value();
          auto srcs = symbol_file->getSourceCodeFiles(addr);
          for (auto src : srcs) {
            if (src.address_bounds().contains(addr)) {
              if (auto iter = src.find_lte_by_pc(addr - symbol_file->baseAddress); iter) {
                this->update_location(tc.get_or_create_bp_location(addr, false));
                tc.pbps.add_bp_location(this);
                tc.emit_breakpoint_event("changed", *this, std::optional<std::string>{});
                return RemoveSubscriber();
              }
            }
          }
          break;
        }
      }
      return KeepSubscriber();
    });
  }
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

  DLOG("mdb", "Hit breakpoint_t {}", id);
  increment_count();
  if (stop_all_threads_when_hit) {
    const auto all_stopped = tc.all_stopped();
    if (all_stopped) {
      tc.emit_stopped_at_breakpoint({.pid = 0, .tid = t.tid}, id, true);
    } else {
      tc.stop_all(&t);
      tc.all_stop.once([&]() { tc.emit_stopped_at_breakpoint({.pid = 0, .tid = t.tid}, id, true); });
    }
  } else {
    tc.emit_stopped_at_breakpoint({.pid = 0, .tid = t.tid}, id, false);
  }
  return bp_hit::normal_stop();
}

TemporaryBreakpoint::TemporaryBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                                         std::optional<Tid> stop_only, std::optional<StopCondition> &&cond,
                                         bool stop_all_threads_when_hit) noexcept
    : Breakpoint(param, kind, stop_only, std::move(cond), stop_all_threads_when_hit, nullptr)
{
}

bp_hit
TemporaryBreakpoint::on_hit(TraceeController &tc, TaskInfo &t) noexcept
{
  const auto res = Breakpoint::on_hit(tc, t);
  if (res.stop) {
    DLOG("mdb", "Hit temporary_breakpoint_t {}", id);
    return bp_hit::stop_retire_bp();
  } else {
    return bp_hit::noop();
  }
}

FinishBreakpoint::FinishBreakpoint(RequiredUserParameters param, Tid stop_only) noexcept
    : UserBreakpoint(param, LocationUserKind::FinishFunction, std::nullopt), stop_only(stop_only)
{
}

bp_hit
FinishBreakpoint::on_hit(TraceeController &tc, TaskInfo &t) noexcept
{
  if (t.tid != stop_only) {
    return bp_hit::noop();
  }
  DLOG("mdb", "Hit finish_bp_t {}", id);
  const auto all_stopped = tc.all_stopped();

  // TODO(simon): This is the point where we should read the value produced by the function we returned from.
  if (all_stopped) {
    tc.emit_stepped_stop({tc.task_leader, tid}, "Finished function", true);
  } else {
    tc.stop_all(&t);
    tc.all_stop.once([&tc, tid = tid]() {
      tc.emit_stepped_stop({tc.task_leader, tid}, "Finished function", true);
    });
  }
  return bp_hit::stop_retire_bp();
}

ResumeToBreakpoint::ResumeToBreakpoint(RequiredUserParameters param, Tid tid) noexcept
    : UserBreakpoint(param, LocationUserKind::ResumeTo, {}), stop_only(tid)
{
}

bp_hit
ResumeToBreakpoint::on_hit(TraceeController &, TaskInfo &t) noexcept
{
  if (t.tid == stop_only) {
    DLOG("mdb", "Hit resume_bp_t {}", id);
    return bp_hit::continue_retire_bp();
  } else {
    return bp_hit::noop();
  }
}

Logpoint::Logpoint(RequiredUserParameters param, std::string logExpression,
                   std::optional<StopCondition> &&stop_condition, std::unique_ptr<UserBpSpec> &&spec) noexcept
    : Breakpoint(param, LocationUserKind::LogPoint, std::nullopt, std::move(stop_condition), false,
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
    : UserBreakpoint(param, LocationUserKind::SharedObjectLoaded, std::nullopt)
{
}

bp_hit
SOLoadingBreakpoint::on_hit(TraceeController &tc, TaskInfo &) noexcept
{
  increment_count();
  tc.on_so_event();
  // we don't stop on shared object loading breakpoints
  return bp_hit::noop();
}

UserBreakpoints::UserBreakpoints(TraceeController &tc) noexcept : tc(tc) {}

u16
UserBreakpoints::new_id() noexcept
{
  return ++current_bp_id;
}

void
UserBreakpoints::add_bp_location(UserBreakpoint *updated_bp) noexcept
{
  ASSERT(updated_bp != nullptr, "Registering a null breakpoint location is not allowed");
  bps_at_loc[updated_bp->address().value()].push_back(updated_bp->id);
  current_pending--;
}

void
UserBreakpoints::add_user(std::shared_ptr<UserBreakpoint> user_bp) noexcept
{
  user_breakpoints[user_bp->id] = user_bp;
  if (user_bp->verified()) {
    bps_at_loc[user_bp->address().value()].push_back(user_bp->id);
  } else {
    ++current_pending;
  }
}

void
UserBreakpoints::remove_bp(u32 id) noexcept
{
  auto bp = user_breakpoints.find(id);
  if (bp == std::end(user_breakpoints)) {
    return;
  }
  bp->second->disable();
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
  if (it == std::end(user_breakpoints))
    return nullptr;

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