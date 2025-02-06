/** LICENSE TEMPLATE */
#pragma once
#include "bp_spec.h"
#include "events/event.h"
#include "events/stop_event.h"
#include "tracee_pointer.h"
#include "typedefs.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/smartptr.h"
#include <functional>

class JSTracer;

namespace mdb {

namespace js {
struct CompileBreakpointCallable;
}

class TraceeController;
struct TaskInfo;
class ObjectFile;
class SymbolFile;

namespace tc {
class TraceeCommandInterface;
};
enum class BreakpointBehavior
{
  StopAllThreadsWhenHit,
  StopOnlyThreadThatHit
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
  BreakpointSpecification *spec;
};

using BpErr = std::variant<MemoryError, ResolveError>;

/** A type that informs the supervisor on what to do with the breakpoint after that breakpoint has been hit.
 * Currently describes if the thread should stop and/or if the breakpoint is to be retired. */
struct BreakpointHitEventResult
{
  // if true, thread that hit breakpoint should be stopped
  EventResult mResult : 31;
  // if true, this user breakpoint should be removed now.
  BreakpointOp mRetireBreakpoint : 1;

  constexpr bool
  ShouldStop() const noexcept
  {
    return mResult == EventResult::Stop || mResult == EventResult::StopAll;
  }

  constexpr bool
  ShouldRetire() const noexcept
  {
    return mRetireBreakpoint == BreakpointOp::Retire;
  }
};

class UserBreakpoints;

class UserBreakpoint;
using StopCondition = std::function<StopEvents(UserBreakpoint *, TaskInfo &t)>;

struct LocationSourceInfo
{
  Immutable<std::string> source_file;
  Immutable<u32> line;
  Immutable<std::optional<u32>> column;
};

class BreakpointLocation
{
  INTERNAL_REFERENCE_COUNT(BreakpointLocation)
  bool installed{true};
  AddrPtr addr;
  std::vector<UserBreakpoint *> users{};
  std::unique_ptr<LocationSourceInfo> source_info;
  friend UserBreakpoints;

public:
  Immutable<u8> original_byte;
  using Ref = RcHandle<BreakpointLocation>;
  static Ref CreateLocation(AddrPtr addr, u8 original) noexcept;
  static Ref CreateLocationWithSource(AddrPtr addr, u8 original,
                                      std::unique_ptr<LocationSourceInfo> &&src_info) noexcept;

  explicit BreakpointLocation(AddrPtr addr, u8 original) noexcept;
  explicit BreakpointLocation(AddrPtr addr, u8 original, std::unique_ptr<LocationSourceInfo> &&src_info) noexcept;
  ~BreakpointLocation() noexcept;

  bool remove_user(tc::TraceeCommandInterface &ctrl, UserBreakpoint &bp) noexcept;
  void enable(Tid tid, tc::TraceeCommandInterface &tc) noexcept;
  void disable(Tid tid, tc::TraceeCommandInterface &tc) noexcept;
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
  Expected<Ref<BreakpointLocation>, BpErr> loc_or_err;
  std::optional<u32> times_to_hit;
  TraceeController &tc;
};

class UserBreakpoint
{
  INTERNAL_REFERENCE_COUNT(UserBreakpoint)
protected:
  using enum EventResult;
  bool mEnabledByUser;
  Ref<BreakpointLocation> mBreakpointLocation;
  std::unique_ptr<BpErr> mInstallError;
  std::unique_ptr<js::CompileBreakpointCallable> mExpression;
  friend UserBreakpoints;

public:
  // The actual interface that sets a breakpoint "in software" of the tracee. Due to the nature of the current
  // design we must carry this reference in `UserBreakpoint`, because on destruction of one (`~UserBreakpoint`), we
  // may be the last user of a `BreakpointLocation` at which point we want to unset it in the tracee. However, we
  // don't do no manual deletion anywhere, so it can/will happen when Ref<UserBreakpoint> gets dropped.
  // Yay? Anyway, it's "just" 8 bytes.
  Immutable<u32> mId;
  Immutable<Tid> mTid;
  Immutable<LocationUserKind> mKind;
  Immutable<u32> mHitCondition;

  explicit UserBreakpoint(RequiredUserParameters param, LocationUserKind kind) noexcept;
  virtual ~UserBreakpoint() noexcept;
  void pre_destruction(tc::TraceeCommandInterface &ctrl) noexcept;

  Ref<BreakpointLocation> GetLocation() noexcept;
  bool IsEnabled() noexcept;
  void Enable(tc::TraceeCommandInterface &ctrl) noexcept;
  void Disable(tc::TraceeCommandInterface &ctrl) noexcept;
  Tid GetTid() noexcept;

  std::optional<AddrPtr> Address() const noexcept;
  bool IsVerified() const noexcept;
  std::optional<u32> Line() const noexcept;
  std::optional<u32> Column() const noexcept;
  std::optional<std::string_view> GetSourceFile() const noexcept;
  std::optional<std::string> GetErrorMessage() const noexcept;
  void UpdateLocation(Ref<BreakpointLocation> bploc) noexcept;
  void SetExpression(std::unique_ptr<js::CompileBreakpointCallable> expression) noexcept;

  virtual BreakpointSpecification *UserProvidedSpec() const noexcept;
  virtual Ref<UserBreakpoint> CloneBreakpoint(UserBreakpoints &breakpointStorage, TraceeController &tc,
                                              Ref<BreakpointLocation> bp) noexcept;

  virtual EventResult EvaluateStopCondition(TaskInfo &t) noexcept;
  /// Evaluate the result of hitting this breakpoint which determines what behavior the task scheduler will take.
  /// `tc` is the relevant supervisor for the task `t` that hit the breakpoint.
  virtual BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept = 0;

  void TraceJs(JSTracer *trace) noexcept;

  template <typename UB, typename... Args>
  static Ref<UB>
  create_user_breakpoint(RequiredUserParameters &&param, Args &&...args) noexcept
  {
    return Ref<UB>::MakeShared(std::move(param), std::move(args)...);
  }
};

class Breakpoint : public UserBreakpoint
{
protected:
  using BpOp = BreakpointOp;
  std::unique_ptr<BreakpointSpecification> mBreakpointSpec;
  u32 mHitCount{0};

public:
  explicit Breakpoint(RequiredUserParameters param, LocationUserKind kind,
                      std::unique_ptr<BreakpointSpecification> spec) noexcept;
  ~Breakpoint() noexcept override = default;
  // Interface to implement
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept override;
  BreakpointSpecification *UserProvidedSpec() const noexcept override;
  Ref<UserBreakpoint> CloneBreakpoint(UserBreakpoints &breakpointStorage, TraceeController &tc,
                                      Ref<BreakpointLocation> bp) noexcept override;

  constexpr void
  IncrementHitCount() noexcept
  {
    ++mHitCount;
  }
};

class TemporaryBreakpoint : public Breakpoint
{
  void remove_self() noexcept;

public:
  explicit TemporaryBreakpoint(RequiredUserParameters param, LocationUserKind kind, std::optional<Tid> stop_only,
                               std::unique_ptr<js::CompileBreakpointCallable> cond) noexcept;
  ~TemporaryBreakpoint() noexcept override = default;
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept override;
};

class FinishBreakpoint : public UserBreakpoint
{
  Tid stop_only;

public:
  explicit FinishBreakpoint(RequiredUserParameters param, Tid stop_only) noexcept;
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class ResumeToBreakpoint : public UserBreakpoint
{
  Tid stop_only;

public:
  explicit ResumeToBreakpoint(RequiredUserParameters param, Tid tid) noexcept;
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class Logpoint : public Breakpoint
{
  std::string mExpressionString;
  void prepareExpression(std::string_view expr) noexcept;
  void EvaluateLog(TaskInfo &t) noexcept;

public:
  explicit Logpoint(RequiredUserParameters param, std::string_view expression,
                    std::unique_ptr<BreakpointSpecification> spec) noexcept;

  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class SOLoadingBreakpoint : public UserBreakpoint
{
public:
  explicit SOLoadingBreakpoint(RequiredUserParameters param) noexcept;
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class UserBreakpoints
{
public:
  using BpId = u32;
  using SourceCodeFileName = std::string;
  using SourceFileBreakpointMap = std::unordered_map<BreakpointSpecification, std::vector<BpId>>;

private:
  TraceeController &tc;
  std::unordered_map<BpId, Ref<UserBreakpoint>> user_breakpoints{};
  std::unordered_map<AddrPtr, std::vector<BpId>> bps_at_loc{};
  std::unordered_map<SourceCodeFileName, SourceFileBreakpointMap> source_breakpoints{};

public:
  explicit UserBreakpoints(TraceeController &tc) noexcept;
  // All these actually map to some form of user breakpoint. The actual "real" software breakpoint that's installed
  // we don't expose here at all, it's behind a shared pointer in the `user_bp_t` types and as such, will die when
  // the last user breakpoint that references it dies (it can also be explicitly killed by instructing a user
  // breakpoint to remove itself from the location's list and if that list becomes empty, the location will die.)

  std::unordered_map<BreakpointSpecification, std::vector<BpId>> fn_breakpoints{};
  std::unordered_map<BreakpointSpecification, BpId> instruction_breakpoints{};

  void on_exec() noexcept;
  void OnProcessExit() noexcept;
  void add_bp_location(const UserBreakpoint &updated_bp) noexcept;
  void add_user(Ref<UserBreakpoint> user_bp) noexcept;
  void remove_bp(u32 id) noexcept;
  Ref<BreakpointLocation> location_at(AddrPtr address) noexcept;
  Ref<UserBreakpoint> GetUserBreakpoint(u32 id) const noexcept;
  std::vector<Ref<UserBreakpoint>> AllUserBreakpoints() const noexcept;
  // Get all user breakpoints that has not been verified (set at an actual address in memory)
  std::vector<Ref<UserBreakpoint>> non_verified() const noexcept;
  SourceFileBreakpointMap &bps_for_source(const SourceCodeFileName &src_file) noexcept;
  SourceFileBreakpointMap &bps_for_source(std::string_view src_file) noexcept;
  std::vector<std::string_view> sources_with_bpspecs() const noexcept;

  template <typename BreakpointT, typename... UserBpArgs>
  Ref<UserBreakpoint>
  create_loc_user(TraceeController &tc, Expected<Ref<BreakpointLocation>, BpErr> &&loc_or_err, Tid tid,
                  UserBpArgs &&...args)
  {
    auto user = UserBreakpoint::create_user_breakpoint<BreakpointT>(
      RequiredUserParameters{
        .tid = tid, .id = new_id(), .loc_or_err = std::move(loc_or_err), .times_to_hit = {}, .tc = tc},
      args...);
    add_user(user);

    return user;
  }

  template <typename BreakpointT, typename... UserBpArgs>
  void
  CreateAndAddUserBreakpoint(TraceeController &tc, Expected<Ref<BreakpointLocation>, BpErr> &&loc_or_err, Tid tid,
                             UserBpArgs &&...args)
  {
    auto user = UserBreakpoint::create_user_breakpoint<BreakpointT>(
      RequiredUserParameters{
        .tid = tid, .id = new_id(), .loc_or_err = std::move(loc_or_err), .times_to_hit = {}, .tc = tc},
      args...);
    add_user(user);
  }
  u16 new_id() noexcept;
};
}; // namespace mdb
