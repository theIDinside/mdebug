/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp.h>
#include <common.h>
#include <common/formatter.h>
#include <common/macros.h>
#include <common/typedefs.h>
#include <event_queue_types.h>
#include <interface/dap/types.h>
#include <mdbsys/stop_status.h>
#include <symbolication/callstack.h>
#include <symbolication/variable_reference.h>
#include <utils/smartptr.h>

// system
#include <linux/sched.h>
#include <sys/user.h>

using namespace std::string_view_literals;

#define FOR_EACH_TRACEE_STATE(STATE)                                                                              \
  STATE(Running, "The task is currently executing.")                                                              \
  STATE(TraceEventStopped, "The thread is currently stopped at a trace event")                                    \
  STATE(ReportedStoppedToUser,                                                                                    \
    "The task has had it's trace event processed and the user has been notified that this thread is stopped.")

ENUM_TYPE_METADATA(TraceeState, FOR_EACH_TRACEE_STATE, DEFAULT_ENUM, u8);

#undef FOR_EACH_TRACEE_STATE

namespace mdb {
namespace tc {
class SupervisorState;
}
class RegisterDescription;

namespace sym {
class Frame;
class CallStack;
class FrameUnwindState;
} // namespace sym

struct CallStackRequest
{
  enum class Type : u8
  {
    Full,
    Partial
  } req;
  int count;

  bool create_frame_ref_ids{ true };

  static CallStackRequest partial(int count) noexcept;
  static CallStackRequest full() noexcept;
};

class TaskInfo
{
  INTERNAL_REFERENCE_COUNT(TaskInfo)
public:
  friend class tc::SupervisorState;
  pid_t mTid;
  u32 mSessionId{ 0 };

  std::optional<PtraceEvent> mUnhandledInitPtraceEvent{ std::nullopt };
  tc::ResumeRequest mResumeRequest{ tc::RunType::Continue, 0 };

  TraceeState mTraceeState : 2 { TraceeState::TraceEventStopped };
  bool mHasStarted : 1 { false }; // fully initialized task. after a clone syscall some setup is required.
                                  // If this is false, it means this task has never been resumed.
  bool mExited : 1 { false };     // task has exited
  bool mReaped : 1 { false };     // task has been reaped after exit
  bool mKilled : 1 { false };
  bool mInvalid : 1 { false };
  bool mRequestedStop : 1 { false };
  bool mRegisterCacheDirty : 1 { true };

private:
  std::unique_ptr<sym::CallStack> mTaskCallstack;
  std::vector<u32> variableReferences{};
  VariableReferenceId mLivenessBoundary;
  u64 mTimestampCreated{ 0 };
  std::unordered_map<VariableReferenceId, Ref<sym::Value>> mVariablesCache{};
  tc::SupervisorState *mSupervisor;
  std::string mThreadName;

public:
  using Ptr = Ref<TaskInfo>;

  using InlinedTid = struct
  {
    Tid mTid;
    Ptr mTask;
  };

  BreakpointStepOverInfo mBreakpointLocationStatus;
  TaskInfo() = delete;
  // Create a new task; either in a user-stopped state or user running state
  TaskInfo(tc::SupervisorState &supervisor, pid_t newTaskTid) noexcept;

  TaskInfo(TaskInfo &&o) noexcept = delete;
  TaskInfo &operator=(TaskInfo &&) noexcept = delete;
  // Delete copy constructors. These are unique values.
  TaskInfo(const TaskInfo &o) noexcept = delete;
  TaskInfo(TaskInfo &o) noexcept = delete;
  TaskInfo &operator=(TaskInfo &t) noexcept = delete;
  TaskInfo &operator=(const TaskInfo &o) = delete;

  ~TaskInfo() noexcept;

  static Ptr CreateTask(tc::SupervisorState &supervisor, pid_t newTaskTid) noexcept;

  AddrPtr GetPc() const noexcept;
  u64 GetDwarfRegister(u64 reg_num) noexcept;
  u64 UnwindBufferRegister(u8 level, u16 register_number) const noexcept;
  void RefreshRegisterCache() noexcept;
  void SetName(std::string_view name) noexcept;
  /**
   * Invalidates the thread, so that it is no longer representative of an actual task. JS code can still hold a
   * reference to it, but it will not be representing an actual task's state in the OS. This happens for instance
   * during reverse execution to before the time when the thread was created.
   */
  void Invalidate() noexcept;
  void ReInit() noexcept;
  void SetExited() noexcept;

  u64
  StartTime() const noexcept
  {
    return mTimestampCreated;
  }

  std::string_view GetName() const noexcept;

  std::span<const AddrPtr> UnwindReturnAddresses(CallStackRequest req) noexcept;
  sym::FrameUnwindState *GetUnwindState(int frameLevel) noexcept;
  tc::SupervisorState *GetSupervisor() const noexcept;

  void StepOverBreakpoint() noexcept;
  void SetAtTraceEventStop() noexcept;
  void SetIsRunning() noexcept;
  bool CanContinue() noexcept;
  void SetInvalidCache() noexcept;
  void AddBreakpointLocationStatus(BreakpointLocation *breakpointLocation) noexcept;
  void ClearBreakpointLocStatus() noexcept;

  /*
   * Checks if this task is stopped, either `stopped_by_tracer` or `stopped` by some execution event, like a signal
   * being delivered, etc.
   */
  bool IsStopped() const noexcept;

  bool
  IsValid() const noexcept
  {
    return !mInvalid;
  }

  sym::CallStack &GetCallstack() noexcept;
  // Add the `VariableReferenceId` to this task, so that once the task is resumed, it can instruct MDB to destroy
  // it's variable context's mapped to these id's (or at least clear it from it's application wide cache, so they
  // no longer can be reached via an ID). If a value in javascript is holding a reference to a variable context,
  // that's fine, it means that value is now no longer "live" (since the task was resumed, we can't guarantee it's
  // correctness or liveness anymore). But it's a shared pointer, because, that value may still want to query the
  // task about things, even when the value itself is stale.
  void AddReference(VariableReferenceId id) noexcept;
  bool VariableReferenceIsStale(VariableReferenceId value) const noexcept;
  void SetValueLiveness(VariableReferenceId value) noexcept;
  void CacheValueObject(VariableReferenceId ref, Ref<sym::Value> value) noexcept;
  Ref<sym::Value> GetVariablesReference(u32 ref) noexcept;
  void RequestedStop() noexcept;
  void ClearRequestedStopFlag() noexcept;
  std::optional<Pid> GetTaskLeaderTid() const noexcept;
  void SetSessionId(u32 sessionId) noexcept;

  void SetResumeType(tc::RunType type) noexcept;
  void SetSignalToForward(int signal) noexcept;
  // Takes the last received/seen signal for this task and clears the signal flag (so we don't accidentally forward
  // it multiple times)
  std::optional<int> ConsumeSignal() noexcept;
  void SetTimestampCreated(u64 time) noexcept;
};
} // namespace mdb

// CallStackRequest
template <> struct std::formatter<mdb::CallStackRequest>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(mdb::CallStackRequest const &req, FormatContext &ctx) const
  {
    if (req.req == mdb::CallStackRequest::Type::Full) {
      return std::format_to(ctx.out(), "all");
    } else {
      return std::format_to(ctx.out(), "{}", req.count);
    }
  }
};

template <> struct std::formatter<mdb::TaskInfo>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(mdb::TaskInfo const &task, FormatContext &ctx)
  {

    std::string_view initialized = "true";
    if (task.mUnhandledInitPtraceEvent) {
      initialized = "false";
    }

    return std::format_to(
      ctx.out(), "[Task {}] {{ tracee state: {}, initialized: {} }}", task.mTid, task.mTraceeState, initialized);
  }
};

template <> struct std::formatter<user_regs_struct>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(user_regs_struct const &ur, FormatContext &ctx)
  {
    return std::format_to(ctx.out(),
      "{{ r15: 0x{:x} r14: 0x{:x} r13: 0x{:x} r12: 0x{:x} rbp: 0x{:x} rbx: 0x{:x} r11: 0x{:x} "
      "r10: 0x{:x} r9: 0x{:x} r8: 0x{:x} rax: 0x{:x} rcx: 0x{:x} rdx: 0x{:x} rsi: 0x{:x} rdi: "
      "0x{:x} orig_rax: 0x{:x} rip: 0x{:x} cs: {} eflags: {} rsp: 0x{:x} ss: {} fs_base: "
      "0x{:x} gs_base: 0x{:x} ds: 0x{:x} es: 0x{:x} fs: 0x{:x} gs: 0x{:x} }}",
      ur.r15,
      ur.r14,
      ur.r13,
      ur.r12,
      ur.rbp,
      ur.rbx,
      ur.r11,
      ur.r10,
      ur.r9,
      ur.r8,
      ur.rax,
      ur.rcx,
      ur.rdx,
      ur.rsi,
      ur.rdi,
      ur.orig_rax,
      ur.rip,
      ur.cs,
      ur.eflags,
      ur.rsp,
      ur.ss,
      ur.fs_base,
      ur.gs_base,
      ur.ds,
      ur.es,
      ur.fs,
      ur.gs);
  }
};