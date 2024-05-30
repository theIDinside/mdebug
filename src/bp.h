#pragma once
#include "common.h"
#include "eval/eval.h"
#include "events/event.h"
#include "typedefs.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/scope_defer.h"
#include <functional>

struct TraceeController;
struct TaskInfo;
struct ObjectFile;
class SymbolFile;

namespace tc {
class TraceeCommandInterface;
};

enum class BreakpointRequestKind : u8
{
  source,
  function,
  instruction,
  data,
  exception,
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

struct SourceBreakpointSpec
{
  u32 line;
  std::optional<u32> column;
  std::optional<std::string> condition;
  std::optional<std::string> log_message;

  // All comparisons assume that this `SourceBreakpoint` actually belongs in the same source file
  // Comparing two `SourceBreakpoint` objects from different source files is non sensical
  friend constexpr auto operator<=>(const SourceBreakpointSpec &l, const SourceBreakpointSpec &r) = default;

  // All comparisons assume that this `SourceBreakpoint` actually belongs in the same source file
  // Comparing two `SourceBreakpoint` objects from different source files is non sensical
  friend constexpr auto
  operator==(const SourceBreakpointSpec &l, const SourceBreakpointSpec &r)
  {
    return l.line == r.line && l.column == r.column && l.condition == r.condition &&
           l.log_message == r.log_message;
  }
};

template <> struct std::hash<SourceBreakpointSpec>
{
  using argument_type = SourceBreakpointSpec;
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

struct FunctionBreakpointSpec
{
  std::string name;
  std::optional<std::string> condition;
  bool is_regex;
  friend constexpr auto operator<=>(const FunctionBreakpointSpec &l, const FunctionBreakpointSpec &r) = default;

  friend constexpr auto
  operator==(const FunctionBreakpointSpec &l, const FunctionBreakpointSpec &r)
  {
    return l.name == r.name && l.condition == r.condition;
  }
};

template <> struct std::hash<FunctionBreakpointSpec>
{
  using argument_type = FunctionBreakpointSpec;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return std::hash<std::string_view>{}(m.name) ^ std::hash<std::string_view>{}(m.condition.value_or(""));
  }
};

struct InstructionBreakpointSpec
{
  std::string instructionReference;
  std::optional<std::string> condition;
  friend constexpr auto operator<=>(const InstructionBreakpointSpec &l,
                                    const InstructionBreakpointSpec &r) = default;
  friend constexpr auto
  operator==(const InstructionBreakpointSpec &l, const InstructionBreakpointSpec &r)
  {
    return l.instructionReference == r.instructionReference && l.condition == r.condition;
  }
};

template <> struct std::hash<InstructionBreakpointSpec>
{
  using argument_type = InstructionBreakpointSpec;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return std::hash<std::string_view>{}(m.instructionReference) ^
           std::hash<std::string_view>{}(m.condition.value_or(""));
  }
};

using UserBpSpec =
  std::variant<std::pair<std::string, SourceBreakpointSpec>, FunctionBreakpointSpec, InstructionBreakpointSpec>;

struct UserRequestedBreakpoint
{
  u32 spec_key;
  BreakpointRequestKind spec_type;
  std::vector<u32> user_ids{};
};

struct MemoryError
{
  int error_no;
  AddrPtr requested_address;
};

struct ResolveError
{
  UserBpSpec *spec;
};

using BpErr = std::variant<MemoryError, ResolveError>;

namespace fmt {
template <> struct formatter<std::pair<std::string, SourceBreakpointSpec>>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const std::pair<std::string, SourceBreakpointSpec> &source_spec, FormatContext &ctx) const
  {
    const auto &spec = source_spec.second;

    auto out = fmt::format_to(ctx.out(), R"(Source = {}:{})", source_spec.first, spec.line);
    if (spec.column) {
      out = fmt::format_to(out, R"(:{})", *spec.column);
    }
    if (spec.condition) {
      out = fmt::format_to(out, R"( with custom hit condition)", *spec.condition);
    }
    if (spec.log_message) {
      out = fmt::format_to(out, R"( and a evaluated log message)", *spec.log_message);
    }

    return out;
  }
};

template <> struct formatter<FunctionBreakpointSpec>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const FunctionBreakpointSpec &spec, FormatContext &ctx) const
  {
    const auto &[name, condition, regex] = spec;
    auto out = fmt::format_to(ctx.out(), R"(Function={}, searched using regex={})", name, regex);
    if (condition.has_value()) {
      out = fmt::format_to(out, R"( with custom hit condition)", *condition);
    }

    return out;
  }
};

template <> struct formatter<InstructionBreakpointSpec>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const InstructionBreakpointSpec &spec, FormatContext &ctx) const
  {
    const auto &[insReference, condition] = spec;
    auto out = fmt::format_to(ctx.out(), R"(Instruction Address={})", insReference);
    if (condition.has_value()) {
      out = fmt::format_to(out, R"( with custom hit condition)", *condition);
    }

    return out;
  }
};

template <> struct formatter<UserBpSpec>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const UserBpSpec &spec, FormatContext &ctx) const
  {
    auto iterator = ctx.out();
    std::visit(
      [&iterator](const auto &var) {
        using T = std::remove_cvref_t<decltype(var)>;
        if constexpr (std::is_same_v<T, std::pair<std::string, SourceBreakpointSpec>>) {
          fmt::format_to(iterator, "{}", var);
        } else if constexpr (std::is_same_v<T, FunctionBreakpointSpec>) {
          fmt::format_to(iterator, "{}", var);
        } else if constexpr (std::is_same_v<T, InstructionBreakpointSpec>) {
          fmt::format_to(iterator, "{}", var);
        } else {
          static_assert(always_false<T>, "Unhandled breakpoint spec type");
        }
      },
      spec);
    return iterator;
  }
};
}; // namespace fmt

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
  AddrPtr addr;
  bool installed{true};
  std::vector<UserBreakpoint *> users{};
  std::unique_ptr<LocationSourceInfo> source_info;

public:
  Immutable<u8> original_byte;
  using shr_ptr = std::shared_ptr<BreakpointLocation>;
  static shr_ptr CreateLocation(AddrPtr addr, u8 original) noexcept;
  static shr_ptr CreateLocationWithSource(AddrPtr addr, u8 original,
                                          std::unique_ptr<LocationSourceInfo> &&src_info) noexcept;

  explicit BreakpointLocation(AddrPtr addr, u8 original) noexcept;
  explicit BreakpointLocation(AddrPtr addr, u8 original, std::unique_ptr<LocationSourceInfo> &&src_info) noexcept;
  ~BreakpointLocation() noexcept;

  bool remove_user(tc::TraceeCommandInterface &ctrl, UserBreakpoint &bp) noexcept;
  void enable(tc::TraceeCommandInterface &tc) noexcept;
  void disable(tc::TraceeCommandInterface &tc) noexcept;
  bool is_installed() const noexcept;
  void add_user(tc::TraceeCommandInterface &ctrl, UserBreakpoint &user) noexcept;
  bool any_user_active() const noexcept;
  std::vector<u32> loc_users() const noexcept;
  const LocationSourceInfo *get_source() const noexcept;

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
  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr> loc_or_err;
  std::optional<u32> times_to_hit;
  bool stop_all;
  TraceeController &tc;
};

class UserBreakpoint
{
private:
  bool enabled_by_user;
  std::shared_ptr<BreakpointLocation> bp;
  u32 on_hit_count{0};
  std::optional<StopCondition> stop_condition;
  std::unique_ptr<BpErr> err;

public:
  static constexpr auto SOURCE_BREAKPOINT = 0;
  static constexpr auto FUNCTION_BREAKPOINT = 1;
  static constexpr auto INSTRUCTION_BREAKPOINT = 2;

  // The actual interface that sets a breakpoint "in software" of the tracee. Due to the nature of the current
  // design we must carry this reference in `UserBreakpoint`, because on destruction of one (`~UserBreakpoint`), we
  // may be the last user of a `BreakpointLocation` at which point we want to unset it in the tracee. However, we
  // don't do no manual deletion anywhere, so it can/will happen when std::shared_ptr<UserBreakpoint> gets dropped.
  // Yay? Anyway, it's "just" 8 bytes.
  Immutable<u32> id;
  Immutable<Tid> tid;
  Immutable<LocationUserKind> kind;
  Immutable<u32> hit_count;
  Immutable<u32> spec_key{};

  explicit UserBreakpoint(RequiredUserParameters param, LocationUserKind kind,
                          std::optional<StopCondition> &&cond) noexcept;
  virtual ~UserBreakpoint() noexcept;
  void pre_destruction(tc::TraceeCommandInterface &ctrl) noexcept;

  std::shared_ptr<BreakpointLocation> bp_location() noexcept;
  void increment_count() noexcept;
  bool is_enabled() noexcept;
  void enable(tc::TraceeCommandInterface &ctrl) noexcept;
  void disable(tc::TraceeCommandInterface &ctrl) noexcept;
  Tid get_tid() noexcept;
  bool check_should_stop(TaskInfo &t) noexcept;
  std::optional<AddrPtr> address() const noexcept;
  bool verified() const noexcept;
  std::optional<u32> line() const noexcept;
  std::optional<u32> column() const noexcept;
  std::optional<std::string_view> source_file() const noexcept;
  std::optional<std::string> error_message() const noexcept;
  virtual UserBpSpec *user_spec() const noexcept;
  void update_location(std::shared_ptr<BreakpointLocation> bploc) noexcept;

  virtual bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept = 0;

  template <typename UserBreakpoint, typename... Args>
  static std::shared_ptr<UserBreakpoint>
  create_user_breakpoint(RequiredUserParameters &&param, Args &&...args) noexcept
  {
    return std::make_shared<UserBreakpoint>(std::move(param), std::move(args)...);
  }
};

class Breakpoint : public UserBreakpoint
{
  std::optional<Tid> stop_only;
  bool stop_all_threads_when_hit;
  std::unique_ptr<UserBpSpec> bp_spec;

public:
  explicit Breakpoint(RequiredUserParameters param, LocationUserKind kind, std::optional<Tid> stop_only,
                      std::optional<StopCondition> &&stop_condition, bool stop_all_threads_when_hit,
                      std::unique_ptr<UserBpSpec> &&spec) noexcept;
  ~Breakpoint() noexcept override = default;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept override;
  UserBpSpec *user_spec() const noexcept override;
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

class Logpoint : public Breakpoint
{
  std::string expressionString;
  std::unique_ptr<eval::Expr> compiledExpression{nullptr};
  void compile_expression() noexcept;

public:
  explicit Logpoint(RequiredUserParameters param, std::string expression,
                    std::optional<StopCondition> &&stop_condition, std::unique_ptr<UserBpSpec> &&spec) noexcept;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class SOLoadingBreakpoint : public UserBreakpoint
{
public:
  explicit SOLoadingBreakpoint(RequiredUserParameters param) noexcept;
  bp_hit on_hit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class UserBreakpoints
{
public:
  using BpId = u32;
  using SourceCodeFileName = std::string;
  using SourceFileBreakpointMap = std::unordered_map<SourceBreakpointSpec, std::vector<BpId>>;

private:
  TraceeController &tc;
  std::unordered_map<BpId, std::shared_ptr<UserBreakpoint>> user_breakpoints{};
  std::unordered_map<AddrPtr, std::vector<BpId>> bps_at_loc{};
  std::unordered_map<SourceCodeFileName, SourceFileBreakpointMap> source_breakpoints{};

public:
  explicit UserBreakpoints(TraceeController &tc) noexcept;
  // All these actually map to some form of user breakpoint. The actual "real" software breakpoint that's installed
  // we don't expose here at all, it's behind a shared pointer in the `user_bp_t` types and as such, will die when
  // the last user breakpoint that references it dies (it can also be explicitly killed by instructing a user
  // breakpoint to remove itself from the location's list and if that list becomes empty, the location will die.)

  std::unordered_map<FunctionBreakpointSpec, std::vector<BpId>> fn_breakpoints{};
  std::unordered_map<InstructionBreakpointSpec, BpId> instruction_breakpoints{};

  void add_bp_location(const UserBreakpoint &updated_bp) noexcept;
  void add_user(std::shared_ptr<UserBreakpoint> user_bp) noexcept;
  void remove_bp(u32 id) noexcept;
  std::shared_ptr<BreakpointLocation> location_at(AddrPtr address) noexcept;
  std::shared_ptr<UserBreakpoint> get_user(u32 id) const noexcept;
  std::vector<std::shared_ptr<UserBreakpoint>> all_users() const noexcept;
  // Get all user breakpoints that has not been verified (set at an actual address in memory)
  std::vector<std::shared_ptr<UserBreakpoint>> non_verified() const noexcept;
  SourceFileBreakpointMap &bps_for_source(const SourceCodeFileName &src_file) noexcept;
  SourceFileBreakpointMap &bps_for_source(std::string_view src_file) noexcept;
  std::vector<std::string_view> sources_with_bpspecs() const noexcept;

  template <typename BreakpointT, typename... UserBpArgs>
  std::shared_ptr<UserBreakpoint>
  create_loc_user(TraceeController &tc, utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr> &&loc_or_err,
                  Tid tid, UserBpArgs &&...args)
  {
    auto user = UserBreakpoint::create_user_breakpoint<BreakpointT>(
      RequiredUserParameters{
        .tid = tid, .id = new_id(), .loc_or_err = std::move(loc_or_err), .times_to_hit = {}, .tc = tc},
      args...);
    add_user(user);

    return user;
  }

private:
  u16 new_id() noexcept;
};