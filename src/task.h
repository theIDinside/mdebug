#pragma once

#include "breakpoint.h"
#include "common.h"
#include "ptrace.h"
#include <linux/sched.h>

using namespace std::string_view_literals;
struct TraceeController;
namespace sym {
struct CallStack;
}

struct CallStackRequest
{
  enum class Type : u8
  {
    Full,
    Partial
  } req;
  u8 count;

  static CallStackRequest partial(u8 count) noexcept;
  static CallStackRequest full() noexcept;
};

struct TaskInfo
{
  friend struct TraceeController;
  static constexpr bool IS_USER_STOPPED = true;
  static constexpr bool IS_USER_RUNNING = false;
  pid_t tid;
  WaitStatus wait_status;
  union
  {
    u16 bit_set;
    struct
    {
      bool stop_collected : 1; // if we're in a "waiting for all stop" state, we check if we've collected the stop
                               // for this task
      bool user_stopped : 1;   // stops visible (possibly) to the user
      bool tracer_stopped : 1; // stops invisible to the user - may be upgraded to user stops. tracer_stop always
                               // occur when waitpid has returned a result for this task
      bool initialized : 1;    // fully initialized task. after a clone syscall some setup is required
      bool cache_dirty : 1;    // register is dirty and requires refetching
      bool rip_dirty : 1;      // rip requires fetching FIXME(simon): Is this even needed anymore?
      bool exited : 1;         // task has exited
    };
  };
  user_regs_struct *registers;
  sym::CallStack *call_stack;
  std::optional<BpStat> bstat;

  TaskInfo() = delete;
  // Create a new task; either in a user-stopped state or user running state
  TaskInfo(pid_t tid, bool user_stopped) noexcept;
  TaskInfo(TaskInfo &&o) noexcept = default;
  TaskInfo &operator=(TaskInfo &&) noexcept = default;
  // Delete copy constructors. These are unique values.
  TaskInfo(const TaskInfo &o) noexcept = delete;
  TaskInfo(TaskInfo &o) noexcept = delete;
  TaskInfo &operator=(TaskInfo &t) noexcept = delete;
  TaskInfo &operator=(const TaskInfo &o) = delete;

  static TaskInfo create_stopped(pid_t tid);
  static TaskInfo create_running(pid_t tid);

  u64 get_register(u64 reg_num) noexcept;
  void cache_registers() noexcept;
  const std::vector<AddrPtr> &return_addresses(TraceeController *tc, CallStackRequest req) noexcept;
  void set_taskwait(TaskWaitResult wait) noexcept;
  void consume_wait() noexcept;

  void step_over_breakpoint(TraceeController *tc, RunType resume_action) noexcept;
  void set_stop() noexcept;
  void initialize() noexcept;
  bool can_continue() noexcept;
  void set_dirty() noexcept;
  void add_bpstat(Breakpoint *bp) noexcept;
  /*
   * Checks if this task is stopped, either `stopped_by_tracer` or `stopped` by some execution event, like a signal
   * being delivered, etc.
   */
  bool is_stopped() const noexcept;
  bool stop_processed() const noexcept;
  WaitStatus pending_wait_status() const noexcept;

private:
  void ptrace_resume(RunType) noexcept;
};

struct TaskStepInfo
{
  Tid tid;
  int steps;
  bool ignore_bps;
  AddrPtr rip;
  void step_taken_to(AddrPtr rip) noexcept;
};

struct TaskVMInfo
{
  static TaskVMInfo from_clone_args(const clone_args &cl_args) noexcept;

  TraceePointer<void> stack_low;
  u64 stack_size;
  TraceePointer<void> tls;
};

namespace fmt {
template <> struct formatter<TaskVMInfo>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(TaskVMInfo const &vm_info, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{{ stack: {}, stack_size: {}, tls: {} }}", vm_info.stack_low.to_string(),
                          vm_info.stack_size, vm_info.tls.to_string());
  }
};
// CallStackRequest
template <> struct formatter<CallStackRequest>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(CallStackRequest const &req, FormatContext &ctx) const
  {
    if (req.req == CallStackRequest::Type::Full) {
      return fmt::format_to(ctx.out(), "all");
    } else {
      return fmt::format_to(ctx.out(), "{}", req.count);
    }
  }
};

template <> struct formatter<TaskInfo>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(TaskInfo const &task, FormatContext &ctx)
  {

    std::string_view wait_status = "None";
    if (task.wait_status.ws != WaitStatusKind::NotKnown) {
      wait_status = to_str(task.wait_status.ws);
    }

    return fmt::format_to(ctx.out(), "[Task {}] {{ stopped: {}, tracer_stopped: {}, wait_status: {} }}", task.tid,
                          task.user_stopped, task.tracer_stopped, wait_status);
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