/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <bp_defs.h>
#include <bp_spec.h>
#include <common/typedefs.h>
#include <events/event.h>
#include <events/stop_event.h>
#include <tracee_pointer.h>
#include <utility>
#include <utils/expected.h>
#include <utils/immutable.h>
#include <utils/smartptr.h>

// stdlib
#include <functional>

namespace mdb {

namespace js {
struct JsBreakpointFunction;
}

class TraceeController;
class TaskInfo;
class ObjectFile;
class SymbolFile;

namespace tc {
class TraceeCommandInterface;
};

struct UserRequestedBreakpoint
{
  u32 mSpecificationKey;
  BreakpointRequestKind mSpecificationType;
  std::vector<u32> mUserBreakpointIds{};
};

struct MemoryError
{
  int mErrorNumber;
  AddrPtr mRequestedAddress;
};

struct ResolveError
{
  BreakpointSpecification *mSpecification;
};

using BreakpointError = std::variant<MemoryError, ResolveError>;

class UserBreakpoint;

/** A type that informs the supervisor on what to do with the breakpoint after that breakpoint has been hit.
 * Currently describes if the thread should stop and/or if the breakpoint is to be retired. */
struct BreakpointHitEventResult
{
  // The user breakpoint that this hit event result is for.
  const UserBreakpoint *mUserBreakpoint{ nullptr };
  // if true, thread that hit breakpoint should be stopped
  EventResult mResult{ EventResult::None };
  // if true, this user breakpoint should be removed now.
  BreakpointOp mRetireBreakpoint{ BreakpointOp::Keep };
  // If there's a conditional for the breakpoint, this signals if it should be kept or removed.
  bool mRetireConditional{ false };

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
  Immutable<std::string> mSourceFile;
  Immutable<u32> mLineNumber;
  Immutable<std::optional<u32>> mColumnNumber;
};

class BreakpointLocation
{
  INTERNAL_REFERENCE_COUNT(BreakpointLocation)
  bool mInstalled{ true };
  AddrPtr mAddress;
  std::vector<UserBreakpoint *> mUserMapping{};
  std::unique_ptr<LocationSourceInfo> mSourceLocation;
  friend UserBreakpoints;

public:
  Immutable<u8> mOriginalByte;
  using Ref = RefPtr<BreakpointLocation>;
  static Ref CreateLocation(AddrPtr address, u8 original) noexcept;
  static Ref CreateLocationWithSource(
    AddrPtr address, u8 original, std::unique_ptr<LocationSourceInfo> sourceLocationInfo) noexcept;

  explicit BreakpointLocation(AddrPtr address, u8 original) noexcept;
  explicit BreakpointLocation(
    AddrPtr address, u8 original, std::unique_ptr<LocationSourceInfo> sourceLocationInfo) noexcept;
  ~BreakpointLocation() noexcept;

  bool RemoveUserOfThis(tc::TraceeCommandInterface &controlInterface, UserBreakpoint &breakpoint) noexcept;
  void Enable(Tid taskId, tc::TraceeCommandInterface &controlInterface) noexcept;
  void Disable(Tid taskId, tc::TraceeCommandInterface &controlInterface) noexcept;
  bool IsInstalled() const noexcept;
  void AddUser(tc::TraceeCommandInterface &controlInterface, UserBreakpoint &breakpoint) noexcept;
  bool AnyUsersActive() const noexcept;
  std::vector<u32> GetUserIds() const noexcept;
  const LocationSourceInfo *GetSourceLocationInfo() const noexcept;

  constexpr AddrPtr
  Address() const noexcept
  {
    return mAddress;
  }
};

struct BreakpointStepOverInfo
{
  RefPtr<BreakpointLocation> mBreakpointLocation{ nullptr };
  TaskInfo *mTaskReference;
  EventResult mStopInfo{ EventResult::None };
  bool mIsSteppingOver : 1 { false };
  bool mFieldShouldRetireBreakpoint : 1 { false };
  bool mConditionalEvaluationFailed : 1 { false };

  constexpr bool
  ShouldBeStopped() const noexcept
  {
    return mStopInfo == EventResult::Stop || mStopInfo == EventResult::StopAll;
  }

  constexpr bool
  IsValid() const noexcept
  {
    return mBreakpointLocation != nullptr;
  }

  /** When a task has had it's (breakpoint) stop handled, either via the fact that it's user stopped (and will
   * continued to be stopped, until a user resumes the task) or, it's been stepped over, so that the breakpoint can
   * be re-inserted, we clear it by setting the address to nullptr, signalling that this task's location status has
   * been handled.*/
  void
  Clear() noexcept
  {
    mBreakpointLocation = nullptr;
    mStopInfo = EventResult::None;
    mIsSteppingOver = false;
    mFieldShouldRetireBreakpoint = false;
    mConditionalEvaluationFailed = false;
  }
};

struct RequiredUserParameters
{
  Tid mTaskId;
  u16 mBreakpointId;
  Expected<Ref<BreakpointLocation>, BreakpointError> mBreakpointLocationResult;
  std::optional<u32> mTimesToHit;
  TraceeController &mControl;
};

class UserBreakpoint
{
  INTERNAL_REFERENCE_COUNT(UserBreakpoint)
protected:
  using enum EventResult;
  bool mEnabledByUser{ true };
  Ref<BreakpointLocation> mBreakpointLocation;
  std::unique_ptr<BreakpointError> mInstallError;
  std::unique_ptr<js::JsBreakpointFunction> mExpression{ nullptr };
  SessionId mProcessId;
  friend UserBreakpoints;

public:
  Immutable<u32> mId;
  Immutable<Tid> mTid;
  Immutable<LocationUserKind> mKind;
  Immutable<u32> mHitCondition;

  explicit UserBreakpoint(RequiredUserParameters param, LocationUserKind kind) noexcept;
  virtual ~UserBreakpoint() noexcept;

  Ref<BreakpointLocation> GetLocation() noexcept;
  bool IsEnabledAndInstalled() noexcept;
  void Enable(tc::TraceeCommandInterface &ctrl) noexcept;
  void Disable(tc::TraceeCommandInterface &ctrl) noexcept;
  Tid GetTid() noexcept;
  std::optional<Tid> GetProcessId() const noexcept;

  std::optional<AddrPtr> Address() const noexcept;
  bool IsVerified() const noexcept;
  std::optional<u32> Line() const noexcept;
  std::optional<u32> Column() const noexcept;
  std::optional<std::string_view> GetSourceFile() const noexcept;
  std::optional<std::pmr::string> GetErrorMessage(std::pmr::memory_resource *rsrc) const noexcept;
  void UpdateLocation(Ref<BreakpointLocation> bploc) noexcept;
  void SetExpression(std::unique_ptr<js::JsBreakpointFunction> expression) noexcept;

  virtual BreakpointSpecification *UserProvidedSpec() const noexcept;
  virtual Ref<UserBreakpoint> CloneBreakpoint(
    UserBreakpoints &breakpointStorage, TraceeController &tc, Ref<BreakpointLocation> bp) noexcept;

  virtual std::optional<BreakpointHitEventResult> EvaluateStopCondition(TaskInfo &t) noexcept;
  /// Evaluate the result of hitting this breakpoint which determines what behavior the task scheduler will take.
  /// `tc` is the relevant supervisor for the task `t` that hit the breakpoint.
  virtual BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept = 0;

  template <typename UB, typename... Args>
  static Ref<UB>
  Create(RequiredUserParameters &&param, Args &&...args) noexcept
  {
    return Ref<UB>::MakeShared(std::move(param), std::move(args)...);
  }
};

class Breakpoint : public UserBreakpoint
{
protected:
  using BpOp = BreakpointOp;
  std::unique_ptr<BreakpointSpecification> mBreakpointSpec;
  u32 mHitCount{ 0 };

public:
  explicit Breakpoint(
    RequiredUserParameters param, LocationUserKind kind, std::unique_ptr<BreakpointSpecification> spec) noexcept;
  ~Breakpoint() noexcept override = default;
  // Interface to implement
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept override;
  BreakpointSpecification *UserProvidedSpec() const noexcept override;
  Ref<UserBreakpoint> CloneBreakpoint(
    UserBreakpoints &breakpointStorage, TraceeController &tc, Ref<BreakpointLocation> bp) noexcept override;

  constexpr void
  IncrementHitCount() noexcept
  {
    ++mHitCount;
  }
};

class FinishBreakpoint : public UserBreakpoint
{
  Tid mStopOnlyTid;

public:
  explicit FinishBreakpoint(RequiredUserParameters param, Tid stopOnlyTaskTid) noexcept;
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class CodeInjectionBoundaryBreakpoint : public UserBreakpoint
{
public:
  explicit CodeInjectionBoundaryBreakpoint(RequiredUserParameters param) noexcept;
  BreakpointHitEventResult OnHit(TraceeController &tc, TaskInfo &t) noexcept final;
};

class ResumeToBreakpoint : public UserBreakpoint
{
  Tid mStopOnlyTid;

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
  explicit Logpoint(RequiredUserParameters param,
    std::string_view expression,
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
  TraceeController &mControl;
  // User breakpoints are breakpoints set by the user.
  std::unordered_map<BpId, Ref<UserBreakpoint>> mUserBreakpoints{};
  std::unordered_map<AddrPtr, std::vector<BpId>> mUserBreakpointsAtAddress{};
  std::unordered_map<SourceCodeFileName, SourceFileBreakpointMap> mSourceCodeBreakpoints{};

public:
  explicit UserBreakpoints(TraceeController &tc) noexcept;
  // All these actually map to some form of user breakpoint. The actual "real" software breakpoint that's
  // installed we don't expose here at all, it's behind a shared pointer in the `user_bp_t` types and as such,
  // will die when the last user breakpoint that references it dies (it can also be explicitly killed by
  // instructing a user breakpoint to remove itself from the location's list and if that list becomes empty, the
  // location will die.)

  std::unordered_map<BreakpointSpecification, std::vector<BpId>> mFunctionBreakpoints{};
  std::unordered_map<BreakpointSpecification, BpId> mInstructionBreakpoints{};

  void OnExec() noexcept;
  void OnProcessExit() noexcept;
  void AddBreakpointLocation(const UserBreakpoint &updatedBreakpoint) noexcept;
  void AddUser(Ref<UserBreakpoint> breakpoint) noexcept;
  // Removes user breakpoint with id `breakpointId`. If this user breakpoint is the last user breakpoint
  // that uses the breakpoint location at that address, it will also uninstall and remove the breakpoint
  // location.
  void RemoveUserBreakpoint(u32 breakpointId) noexcept;
  Ref<BreakpointLocation> GetLocationAt(AddrPtr address) noexcept;
  Ref<UserBreakpoint> GetUserBreakpoint(u32 id) const noexcept;
  std::vector<Ref<UserBreakpoint>> AllUserBreakpoints() const noexcept;
  // Get all user breakpoints that has not been verified (set at an actual address in memory)
  std::vector<Ref<UserBreakpoint>> GetNonVerified() const noexcept;
  SourceFileBreakpointMap &GetBreakpointsFromSourceFile(const SourceCodeFileName &sourceCodeFileName) noexcept;
  SourceFileBreakpointMap &GetBreakpointsFromSourceFile(std::string_view sourceCodeFileName) noexcept;
  std::vector<std::string_view> GetSourceFilesWithBreakpointSpecs() const noexcept;

  template <typename BreakpointT, typename... UserBpArgs>
  Ref<UserBreakpoint>
  CreateBreakpointLocationUser(TraceeController &control,
    Expected<Ref<BreakpointLocation>, BreakpointError> &&breakpointLocationResult,
    Tid tid,
    UserBpArgs &&...args)
  {
    auto user =
      UserBreakpoint::Create<BreakpointT>(RequiredUserParameters{ .mTaskId = tid,
                                            .mBreakpointId = NewBreakpointId(),
                                            .mBreakpointLocationResult = std::move(breakpointLocationResult),
                                            .mTimesToHit = {},
                                            .mControl = control },
        args...);
    AddUser(user);

    return user;
  }

  static Expected<Ref<BreakpointLocation>, BreakpointError> CreateBreakpointLocation(
    TraceeController &control, AddrPtr address) noexcept;

  template <typename BreakpointT, typename... UserBpArgs>
  Ref<UserBreakpoint>
  CreateBreakpointLocationUser(TraceeController &control, AddrPtr address, Tid tid, UserBpArgs &&...args)
  {
    auto user = UserBreakpoint::Create<BreakpointT>(
      RequiredUserParameters{ .mTaskId = tid,
        .mBreakpointId = NewBreakpointId(),
        .mBreakpointLocationResult = CreateBreakpointLocation(control, address),
        .mTimesToHit = {},
        .mControl = control },
      args...);

    return user;
  }

  template <typename BreakpointT, typename... UserBpArgs>
  void
  CreateAndAddUserBreakpoint(TraceeController &control,
    Expected<Ref<BreakpointLocation>, BreakpointError> &&breakpointLocationResult,
    Tid tid,
    UserBpArgs &&...args)
  {
    auto user =
      UserBreakpoint::Create<BreakpointT>(RequiredUserParameters{ .mTaskId = tid,
                                            .mBreakpointId = NewBreakpointId(),
                                            .mBreakpointLocationResult = std::move(breakpointLocationResult),
                                            .mTimesToHit = {},
                                            .mControl = control },
        args...);
    AddUser(user);
  }
  u16 NewBreakpointId() noexcept;
};
}; // namespace mdb
