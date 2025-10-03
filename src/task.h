/** LICENSE TEMPLATE */
#pragma once

// mdb
#include "common/typedefs.h"
#include <bp.h>
#include <common.h>
#include <common/formatter.h>
#include <common/macros.h>
#include <interface/dap/types.h>
#include <interface/tracee_command/tracee_command_interface.h>
#include <mdbsys/stop_status.h>
#include <symbolication/callstack.h>
#include <symbolication/variable_reference.h>
#include <utils/smartptr.h>

// system
#include <linux/sched.h>
#include <sys/user.h>

using namespace std::string_view_literals;
namespace mdb {
class TraceeController;
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

struct TaskRegisters
{
  Immutable<ArchType> arch;
  Immutable<TargetFormat> mRegisterFormat;

  TaskRegisters() noexcept = default;
  TaskRegisters(TargetFormat format, gdb::ArchictectureInfo *archInfo);
  TaskRegisters(TaskRegisters &&) noexcept = default;
  TaskRegisters &operator=(TaskRegisters &&) noexcept = default;

  union
  {
    user_regs_struct *registers;
    RegisterDescription *registerFile;
  };

  AddrPtr GetPc() const noexcept;
  u64 GetRegister(u32 regNumber) const noexcept;
};

class TaskInfo
{
  INTERNAL_REFERENCE_COUNT(TaskInfo)
public:
  enum class SupervisorState : u8
  {
    Traced,
    Exited,
    Killed = Exited,
    Detached
  };

  friend class TraceeController;
  pid_t mTid;
  u32 mSessionId{ 0 };
  StopStatus mLastStopStatus;
  TargetFormat mTargetFormat;
  tc::ResumeRequest mResumeRequest{ tc::RunType::Continue, 0 };

  union
  {
    struct
    {
      bool mUserVisibleStop : 1; // stops visible (possibly) to the user
      /* stops invisible to the user - may be upgraded to user stops. tracer_stop always occur when waitpid has
       * returned a result for this task, or when a remote has sent a stop reply for a thread if the remote is also
       * in "not non-stop mode", *all* threads get set to true on each stop (and false on each continue) regardless
       * of what thread the user is operating on. It's "all stop mode". */
      bool mTracerVisibleStop : 1;
      bool mInitialized : 1; // fully initialized task. after a clone syscall some setup is required
      // register is dirty and requires refetching
      bool mRegisterCacheDirty : 1 { true };
      // rip requires fetching FIXME(simon): Is this even needed anymore?
      bool mInstructionPointerDirty : 1 { true };
      bool mExited : 1;           // task has exited
      bool mReaped : 1 { false }; // task has been reaped after exit
      bool mKilled : 1 { false };
      bool mRequestedStop : 1 { false };
    };
  };

private:
  TaskRegisters regs;
  std::unique_ptr<sym::CallStack> mTaskCallstack;
  std::vector<u32> variableReferences{};
  VariableReferenceId mLivenessBoundary;
  std::unordered_map<VariableReferenceId, Ref<sym::Value>> mVariablesCache{};
  TraceeController *mSupervisor;

  // Unititialized thread constructor
  TaskInfo(pid_t newTaskTid) noexcept;

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
  TaskInfo(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isUserStopped) noexcept;

  TaskInfo(TaskInfo &&o) noexcept = delete;
  TaskInfo &operator=(TaskInfo &&) noexcept = delete;
  // Delete copy constructors. These are unique values.
  TaskInfo(const TaskInfo &o) noexcept = delete;
  TaskInfo(TaskInfo &o) noexcept = delete;
  TaskInfo &operator=(TaskInfo &t) noexcept = delete;
  TaskInfo &operator=(const TaskInfo &o) = delete;

  ~TaskInfo() noexcept = default;

  static Ptr CreateTask(tc::TraceeCommandInterface &supervisor, pid_t newTaskTid, bool isRunning) noexcept;

  static Ptr CreateUnInitializedTask(WaitPidResult wait) noexcept;

  user_regs_struct *NativeRegisters() const noexcept;
  RegisterDescription *RemoteX86Registers() const noexcept;
  void RemoteFromHexdigitEncoding(std::string_view hex_encoded) noexcept;
  const TaskRegisters &GetRegisterCache() const;
  void SetRegisterCacheTo(u8 *buffer, size_t bufferSize);
  u64 GetRegister(u64 reg_num) noexcept;
  u64 UnwindBufferRegister(u8 level, u16 register_number) const noexcept;
  void StoreToRegisterCache(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept;
  void RefreshRegisterCache() noexcept;

  std::span<const AddrPtr> UnwindReturnAddresses(CallStackRequest req) noexcept;
  sym::FrameUnwindState *GetUnwindState(int frameLevel) noexcept;
  TraceeController *GetSupervisor() const noexcept;

  void SetTaskWait(WaitPidResult wait) noexcept;

  void StepOverBreakpoint() noexcept;
  void SetUserVisibleStop() noexcept;
  void SetIsRunning() noexcept;
  void InitializeThread(tc::TraceeCommandInterface &supervisor, bool restart) noexcept;
  bool CanContinue() noexcept;
  void SetInvalidCache() noexcept;
  void SetUpdated() noexcept;
  void AddBreakpointLocationStatus(BreakpointLocation *breakpointLocation) noexcept;
  void ClearBreakpointLocStatus() noexcept;

  /*
   * Checks if this task is stopped, either `stopped_by_tracer` or `stopped` by some execution event, like a signal
   * being delivered, etc.
   */
  bool IsStopped() const noexcept;
  bool IsStopProcessed() const noexcept;
  void CollectStop() noexcept;

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
  void SetForwardedSignal(int signal) noexcept;
  // Takes the last received/seen signal for this task and clears the signal flag (so we don't accidentally forward
  // it multiple times)
  std::optional<int> ConsumeSignal() noexcept;
};

struct TaskVMInfo
{
  static TaskVMInfo from_clone_args(const clone_args &cl_args) noexcept;

  TraceePointer<void> stack_low;
  u64 stack_size;
  TraceePointer<void> tls;
};

struct ExecutionContext
{
  TraceeController *tc;
  TaskInfo *t;
};
} // namespace mdb

template <> struct std::formatter<mdb::TaskVMInfo>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(mdb::TaskVMInfo const &vm_info, FormatContext &ctx)
  {
    return std::format_to(
      ctx.out(), "{{ stack: {}, stack_size: {}, tls: {} }}", vm_info.stack_low, vm_info.stack_size, vm_info.tls);
  }
};
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

    std::string_view wait_status = "None";
    if (task.mLastStopStatus.ws != StopKind::NotKnown) {
      wait_status = Enums::ToString(task.mLastStopStatus.ws);
    }

    return std::format_to(ctx.out(),
      "[Task {}] {{ stopped: {}, tracer_stopped: {}, wait_status: {} }}",
      task.mTid,
      task.mUserVisibleStop,
      task.mTracerVisibleStop,
      wait_status);
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