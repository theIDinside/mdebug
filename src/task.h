/** LICENSE TEMPLATE */
#pragma once

#include "bp.h"
#include "common.h"
#include "interface/dap/types.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "symbolication/callstack.h"
#include "utils/smartptr.h"
#include <linux/sched.h>
#include <mdbsys/ptrace.h>
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

  bool create_frame_ref_ids{true};

  static CallStackRequest partial(int count) noexcept;
  static CallStackRequest full() noexcept;
};

struct TaskRegisters
{
  Immutable<ArchType> arch;
  Immutable<TargetFormat> mRegisterFormat;
  bool rip_dirty : 1 {true};
  bool cache_dirty : 1 {true};

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

struct TaskInfo
{
  INTERNAL_REFERENCE_COUNT(TaskInfo)
public:
  enum class SupervisorState
  {
    Traced,
    Exited,
    Killed = Exited,
    Detached
  };

  friend class TraceeController;
  pid_t mTid;
  WaitStatus mLastWaitStatus;
  TargetFormat mTargetFormat;
  tc::ResumeAction mLastResumeAction;
  std::optional<tc::ResumeAction> mNextResumeAction{};
  bool firstResume{true};
  SupervisorState mState{SupervisorState::Traced};

  union
  {
    u16 bit_set;
    struct
    {
      bool mHasProcessedStop : 1; // if we're in a "waiting for all stop" state, we check if we've collected the
                                  // stop for this task
      bool mUserVisibleStop : 1;  // stops visible (possibly) to the user
      bool
        mTracerVisibleStop : 1; // stops invisible to the user - may be upgraded to user stops. tracer_stop always
                                // occur when waitpid has returned a result for this task, or when a remote has
                                // sent a stop reply for a thread if the remote is also in "not non-stop mode",
                                // *all* threads get set to true on each stop (and false on each continue)
                                // regardless of what thread the user is operating on. It's "all stop mode".
      bool initialized : 1;     // fully initialized task. after a clone syscall some setup is required
      bool mRegisterCacheDirty : 1;      // register is dirty and requires refetching
      bool mInstructionPointerDirty : 1; // rip requires fetching FIXME(simon): Is this even needed anymore?
      bool exited : 1;                   // task has exited
      bool reaped : 1;                   // task has been reaped after exit
      bool killed : 1 {false};
      bool bfRequestedStop : 1 {false};
    };
  };

private:
  TaskRegisters regs;
  std::unique_ptr<sym::CallStack> mTaskCallstack;
  std::vector<u32> variableReferences{};
  std::unordered_map<u32, SharedPtr<sym::Value>> valobj_cache{};
  TraceeController *mSupervisor;

  // Unititialized thread constructor
  TaskInfo(pid_t newTaskTid) noexcept;

public:
  using Ptr = Ref<TaskInfo>;

  using TaskInfoEntry = struct
  {
    Tid mTid;
    Ptr mTask;
  };

  std::optional<LocationStatus> mBreakpointLocationStatus;
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

  static Ptr CreateUnInitializedTask(TaskWaitResult wait) noexcept;

  user_regs_struct *native_registers() const noexcept;
  RegisterDescription *remote_x86_registers() const noexcept;
  void remote_from_hexdigit_encoding(std::string_view hex_encoded) noexcept;
  const TaskRegisters &GetRegisterCache() const;
  u64 get_register(u64 reg_num) noexcept;
  u64 unwind_buffer_register(u8 level, u16 register_number) const noexcept;
  void StoreToRegisterCache(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept;

  std::span<const AddrPtr> return_addresses(TraceeController *tc, CallStackRequest req) noexcept;
  sym::FrameUnwindState *GetUnwindState(int frameLevel) noexcept;
  TraceeController *GetSupervisor() const noexcept;

  void set_taskwait(TaskWaitResult wait) noexcept;

  void step_over_breakpoint(TraceeController *tc, tc::ResumeAction resume_action) noexcept;
  void set_stop() noexcept;
  void SetCurrentResumeAction(tc::ResumeAction type) noexcept;
  void InitializeThread(tc::TraceeCommandInterface &supervisor, bool restart) noexcept;
  bool can_continue() noexcept;
  void set_dirty() noexcept;
  void set_updated() noexcept;
  void AddBreakpointLocationStatus(AddrPtr address) noexcept;
  std::optional<LocationStatus> clear_bpstat() noexcept;
  /*
   * Checks if this task is stopped, either `stopped_by_tracer` or `stopped` by some execution event, like a signal
   * being delivered, etc.
   */
  bool is_stopped() const noexcept;
  bool stop_processed() const noexcept;
  void collect_stop() noexcept;
  WaitStatus pending_wait_status() const noexcept;

  sym::CallStack &get_callstack() noexcept;
  void clear_stop_state() noexcept;
  void add_reference(u32 id) noexcept;
  void cache_object(u32 ref, SharedPtr<sym::Value> value) noexcept;
  SharedPtr<sym::Value> get_maybe_value(u32 ref) noexcept;
  void RequestedStop() noexcept;
  void ClearRequestedStopFlag() noexcept;
  void SetTracerState(SupervisorState state) noexcept;
  std::optional<Pid> GetTaskLeaderTid() const noexcept;
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

namespace fmt {
template <> struct formatter<mdb::TaskVMInfo>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(mdb::TaskVMInfo const &vm_info, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{{ stack: {}, stack_size: {}, tls: {} }}", vm_info.stack_low,
                          vm_info.stack_size, vm_info.tls);
  }
};
// CallStackRequest
template <> struct formatter<mdb::CallStackRequest>
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
      return fmt::format_to(ctx.out(), "all");
    } else {
      return fmt::format_to(ctx.out(), "{}", req.count);
    }
  }
};

template <> struct formatter<mdb::TaskInfo>
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
    if (task.mLastWaitStatus.ws != mdb::WaitStatusKind::NotKnown) {
      wait_status = to_str(task.mLastWaitStatus.ws);
    }

    return fmt::format_to(ctx.out(), "[Task {}] {{ stopped: {}, tracer_stopped: {}, wait_status: {} }}", task.mTid,
                          task.mUserVisibleStop, task.mTracerVisibleStop, wait_status);
  }
};

template <> struct formatter<user_regs_struct>
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
    return fmt::format_to(ctx.out(),
                          "{{ r15: 0x{:x} r14: 0x{:x} r13: 0x{:x} r12: 0x{:x} rbp: 0x{:x} rbx: 0x{:x} r11: 0x{:x} "
                          "r10: 0x{:x} r9: 0x{:x} r8: 0x{:x} rax: 0x{:x} rcx: 0x{:x} rdx: 0x{:x} rsi: 0x{:x} rdi: "
                          "0x{:x} orig_rax: 0x{:x} rip: 0x{:x} cs: {} eflags: {} rsp: 0x{:x} ss: {} fs_base: "
                          "0x{:x} gs_base: 0x{:x} ds: 0x{:x} es: 0x{:x} fs: 0x{:x} gs: 0x{:x} }}",
                          ur.r15, ur.r14, ur.r13, ur.r12, ur.rbp, ur.rbx, ur.r11, ur.r10, ur.r9, ur.r8, ur.rax,
                          ur.rcx, ur.rdx, ur.rsi, ur.rdi, ur.orig_rax, ur.rip, ur.cs, ur.eflags, ur.rsp, ur.ss,
                          ur.fs_base, ur.gs_base, ur.ds, ur.es, ur.fs, ur.gs);
  }
};
}; // namespace fmt