#pragma once
#include "common.h"
#include "events/event.h"
#include "typedefs.h"
#include "utils/immutable.h"
#include "utils/scope_defer.h"
#include <functional>

struct TraceeController;
struct TaskInfo;
struct ObjectFile;

enum class BreakpointRequestKind : u8
{
  source,
  function,
  instruction,
  data,
};

enum class LocationUserKind : u8
{
  Address,
  Source,
  Function,
  FinishFunction,
  LogPoint,
  ResumeTo,
  SharedObjectLoaded,
  Exception,
  LongJump
};

struct ThreadStopped
{
};
/** A type that informs the supervisor on what to do with the breakpoint after that breakpoint has been hit.
 * Currently describes if the thread should stop and/or if the breakpoint is to be retired. */
struct bp_hit
{
  // if true, thread that hit breakpoint should be stopped
  bool stop : 1;
  // if true, this user breakpoint should be removed now.
  bool retire_bp : 1;

  static bp_hit
  noop() noexcept
  {
    return bp_hit{false, false};
  }

  static bp_hit
  normal_stop() noexcept
  {
    return bp_hit{true, false};
  }

  static bp_hit
  continue_retire_bp() noexcept
  {
    return bp_hit{false, true};
  }

  static bp_hit
  stop_retire_bp() noexcept
  {
    return bp_hit{true, true};
  }
};

class UserBreakpoints;

class UserBreakpoint;
using StopCondition = std::function<bool(UserBreakpoint *, TaskInfo &t)>;

struct LocationSourceInfo
{
  Immutable<std::string> source_file;
  Immutable<u32> line;
  Immutable<std::optional<u32>> column;
};

class BreakpointLocation
{
  friend class UserBreakpoint;

  AddrPtr addr;
  u8 original_byte;
  bool installed{true};
  std::vector<UserBreakpoint *> users{};
  std::unique_ptr<LocationSourceInfo> source_info;

  bool remove_user(NonNullPtr<UserBreakpoint> bp) noexcept;

public:
  static std::shared_ptr<BreakpointLocation> CreateLocation(AddrPtr addr, u8 original) noexcept;
  static std::shared_ptr<BreakpointLocation>
  CreateLocationWithSource(AddrPtr addr, u8 original, std::unique_ptr<LocationSourceInfo> &&src_info) noexcept;

  explicit BreakpointLocation(AddrPtr addr, u8 original) noexcept;
  explicit BreakpointLocation(AddrPtr addr, u8 original, std::unique_ptr<LocationSourceInfo> &&src_info) noexcept;
  ~BreakpointLocation() noexcept;

  void enable(Tid tid) noexcept;
  void disable(Tid tid) noexcept;
  void add_user(UserBreakpoint &user) noexcept;
  bool any_user_active() const noexcept;
  std::vector<u32> loc_users() const noexcept;

  constexpr AddrPtr
  address() const noexcept
  {
    return addr;
  }
};

struct LocationStatus
{
  AddrPtr loc;
  bool should_resume;
  bool stepped_over;
  bool re_enable_bp;
};

struct RequiredUserParameters
{
  Tid tid;
  u16 id;
  std::shared_ptr<BreakpointLocation> loc;
  std::optional<u32> times_to_hit;
  bool stop_all;
  TraceeController &tc;
};

class UserBreakpoint
{
private:
  bool enabled;
  std::shared_ptr<BreakpointLocation> bp;
  u32 on_hit_count;
  std::optional<StopCondition> stop_condition;
  Publisher<ObjectFile *> *objfile_subscriber{nullptr};

public:
  Immutable<u32> id;
  Immutable<Tid> tid;
  Immutable<LocationUserKind> kind;
  Immutable<u32> hit_count;

  explicit UserBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                          std::optional<StopCondition> &&cond) noexcept;
  virtual ~UserBreakpoint() noexcept;

  // Removes the breakpoint location from this user breakpoint - essentially nullifying the object as it no longer
  // actually represents a live breakpoint no more.

  void remove_location() noexcept;
  std::shared_ptr<BreakpointLocation> bp_location() noexcept;
  void increment_count() noexcept;
  bool is_enabled() noexcept;
  void enable() noexcept;
  void disable() noexcept;
  Tid get_tid() noexcept;
  bool check_should_stop(TaskInfo &t) noexcept;
  std::optional<AddrPtr> address() const noexcept;
  bool verified() const noexcept;
  std::optional<u32> line() const noexcept;
  std::optional<u32> column() const noexcept;
  std::optional<std::string_view> source_file() const noexcept;

  virtual bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept = 0;

  template <typename UserBreakpoint, typename... Args>
  static std::shared_ptr<UserBreakpoint>
  create_user_breakpoint(RequiredUserParameters param, Args... args) noexcept
  {
    return std::make_shared<UserBreakpoint>(std::move(param), args...);
  }
};

class Breakpoint : public UserBreakpoint
{
  std::optional<Tid> stop_only;
  bool stop_all_threads_when_hit;

public:
  explicit Breakpoint(RequiredUserParameters param, LocationUserKind kind, std::optional<Tid> stop_only,
                      std::optional<StopCondition> &&stop_condition, bool stop_all_threads_when_hit) noexcept;
  ~Breakpoint() noexcept override = default;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept override;
};

class TemporaryBreakpoint : public Breakpoint
{
  void remove_self() noexcept;

public:
  explicit TemporaryBreakpoint(RequiredUserParameters param, LocationUserKind kind, std::optional<Tid> stop_only,
                               std::optional<StopCondition> &&cond, bool stop_all_threads_when_hit) noexcept;
  ~TemporaryBreakpoint() noexcept override = default;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept override;
};

class FinishBreakpoint : public UserBreakpoint
{
  Tid stop_only;

public:
  explicit FinishBreakpoint(RequiredUserParameters param, Tid stop_only) noexcept;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class ResumeToBreakpoint : public UserBreakpoint
{
  Tid stop_only;

public:
  explicit ResumeToBreakpoint(RequiredUserParameters param, Tid tid) noexcept;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class Logpoint : public UserBreakpoint
{
public:
  explicit Logpoint(RequiredUserParameters param) noexcept;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class SOLoadingBreakpoint : public UserBreakpoint
{
public:
  explicit SOLoadingBreakpoint(RequiredUserParameters param) noexcept;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept final;
};

struct SourceBreakpoint
{
  u32 line;
  std::optional<u32> column;
  std::optional<std::string> condition;
  std::optional<std::string> log_message;

  // All comparisons assume that this `SourceBreakpoint` actually belongs in the same source file
  // Comparing two `SourceBreakpoint` objects from different source files is non sensical
  friend constexpr auto operator<=>(const SourceBreakpoint &l, const SourceBreakpoint &r) = default;

  // All comparisons assume that this `SourceBreakpoint` actually belongs in the same source file
  // Comparing two `SourceBreakpoint` objects from different source files is non sensical
  friend constexpr auto
  operator==(const SourceBreakpoint &l, const SourceBreakpoint &r)
  {
    return l.line == r.line && l.column == r.column && l.condition == r.condition &&
           l.log_message == r.log_message;
  }
};

template <> struct std::hash<SourceBreakpoint>
{
  using argument_type = SourceBreakpoint;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    const auto u32_hasher = std::hash<u32>{};

    const auto line_col_hash =
        m.column.transform([&h = u32_hasher, line = m.line](auto col) { return h(col) ^ h(line); })
            .or_else([&h = u32_hasher, line = m.line]() { return std::optional{h(line)}; })
            .value();

    if (m.condition && m.log_message) {
      return line_col_hash ^ std::hash<std::string_view>{}(m.condition.value()) ^
             std::hash<std::string_view>{}(m.log_message.value());
    } else if (!m.condition && m.log_message) {
      return line_col_hash ^ std::hash<std::string_view>{}(m.log_message.value());
    } else if (m.condition && !m.log_message) {
      return line_col_hash ^ std::hash<std::string_view>{}(m.condition.value());
    } else {
      return line_col_hash;
    }
  }
};

struct FunctionBreakpoint
{
  std::string name;
  std::optional<std::string> condition;
  friend constexpr auto operator<=>(const FunctionBreakpoint &l, const FunctionBreakpoint &r) = default;

  friend constexpr auto
  operator==(const FunctionBreakpoint &l, const FunctionBreakpoint &r)
  {
    return l.name == r.name && l.condition == r.condition;
  }
};

template <> struct std::hash<FunctionBreakpoint>
{
  using argument_type = FunctionBreakpoint;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return std::hash<std::string_view>{}(m.name) ^ std::hash<std::string_view>{}(m.condition.value_or(""));
  }
};

struct InstructionBreakpoint
{
  std::string instructionReference;
  std::optional<std::string> condition;
  friend constexpr auto operator<=>(const InstructionBreakpoint &l, const InstructionBreakpoint &r) = default;
  friend constexpr auto
  operator==(const InstructionBreakpoint &l, const InstructionBreakpoint &r)
  {
    return l.instructionReference == r.instructionReference && l.condition == r.condition;
  }
};

template <> struct std::hash<InstructionBreakpoint>
{
  using argument_type = InstructionBreakpoint;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return std::hash<std::string_view>{}(m.instructionReference) ^
           std::hash<std::string_view>{}(m.condition.value_or(""));
  }
};

class UserBreakpoints
{
  using BpId = u32;

  TraceeController &tc;
  u32 current_bp_id{0};
  u32 current_pending{0};
  std::unordered_map<u32, std::shared_ptr<UserBreakpoint>> user_breakpoints{};
  std::unordered_map<AddrPtr, std::vector<BpId>> bps_at_loc{};
  u16 new_id() noexcept;

public:
  explicit UserBreakpoints(TraceeController &tc) noexcept;
  // All these actually map to some form of user breakpoint. The actual "real" software breakpoint that's installed
  // we don't expose here at all, it's behind a shared pointer in the `user_bp_t` types and as such, will die when
  // the last user breakpoint that references it dies (it can also be explicitly killed by instructing a user
  // breakpoint to remove itself from the location's list and if that list becomes empty, the location will die.)
  std::unordered_map<std::string, std::unordered_map<SourceBreakpoint, BpId>> source_breakpoints{};
  std::unordered_map<FunctionBreakpoint, std::vector<BpId>> fn_breakpoints{};
  std::unordered_map<InstructionBreakpoint, BpId> instruction_breakpoints{};

  void add_user(std::shared_ptr<UserBreakpoint> user_bp) noexcept;
  void remove_bp(u32 id) noexcept;
  std::shared_ptr<BreakpointLocation> location_at(AddrPtr address) noexcept;
  std::shared_ptr<UserBreakpoint> get_user(u32 id) const noexcept;
  std::vector<std::shared_ptr<UserBreakpoint>> all_users() const noexcept;

  template <typename BreakpointT, typename... UserBpArgs>
  std::shared_ptr<UserBreakpoint>
  create_loc_user(TraceeController &tc, std::shared_ptr<BreakpointLocation> bp_location, Tid tid,
                  UserBpArgs... args)
  {
    RequiredUserParameters param{
        .tid = tid, .id = new_id(), .loc = std::move(bp_location), .times_to_hit = {}, .tc = tc};

    auto user = UserBreakpoint::create_user_breakpoint<BreakpointT>(param, args...);
    add_user(user);

    return user;
  }
};