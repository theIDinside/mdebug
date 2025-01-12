#pragma once

#include "interface/dap/dap_defs.h"
#include "symbolication/dwarf/lnp.h"
#include <symbolication/callstack.h>
#include <unordered_map>

class TraceeController;
struct BpStat;
struct TaskInfo;

struct TraceEvent;

namespace tc {
class TraceeCommandInterface;
struct ProcessedStopEvent;
} // namespace tc

namespace ptracestop {

class StopHandler;

class ThreadProceedAction
{
public:
  ThreadProceedAction(TraceeController &ctrl, TaskInfo &task) noexcept;
  virtual void cancel() noexcept;

  // Abstract Interface
  virtual ~ThreadProceedAction() noexcept = default;
  virtual bool HasCompleted(bool was_stopped) const noexcept = 0;
  virtual void Proceed() noexcept = 0;
  virtual void UpdateStepped() noexcept = 0;

protected:
  tc::TraceeCommandInterface &mControlInterface;
  TraceeController &mSupervisor;
  TaskInfo &task;
  bool cancelled;
};

// A proceed-handler / stop-handler, that stops a task immediately, possibly to perform some one-time task (like
// for instance, notifying an observer)
class StopImmediately : public ThreadProceedAction
{
public:
  StopImmediately(TraceeController &ctrl, TaskInfo &task, ui::dap::StoppedReason reason) noexcept;
  ~StopImmediately() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  void notify_stopped() noexcept;
  ui::dap::StoppedReason reason;
};

class InstructionStep : public ThreadProceedAction
{
public:
  InstructionStep(TraceeController &ctrl, TaskInfo &task, int steps) noexcept;
  ~InstructionStep() override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  int steps_requested;
  int steps_taken;
};

class LineStep : public ThreadProceedAction
{
public:
  LineStep(TraceeController &ctrl, TaskInfo &task, int lines) noexcept;
  ~LineStep() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  // Installs resume-to breakpoint at `address`
  void InstallBreakpoint(AddrPtr address) noexcept;
  void MaybeSetDone(bool isDone) noexcept;

  int lines_requested;
  int lines_stepped;
  bool mIsDone;
  bool resumed_to_resume_addr;
  sym::Frame startFrame;
  sym::dw::LineTableEntry entry;
  std::shared_ptr<UserBreakpoint> resume_bp{nullptr};
};

class FinishFunction : public ThreadProceedAction
{
public:
  FinishFunction(TraceeController &ctrl, TaskInfo &t, std::shared_ptr<UserBreakpoint> bp,
                 bool should_clean_up) noexcept;
  ~FinishFunction() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  std::shared_ptr<UserBreakpoint> bp;
  bool should_cleanup;
};

template <typename A>
constexpr std::string_view
action_name()
{
  if constexpr (std::is_same_v<A, InstructionStep>) {
    return "Instruction Step";
  } else if constexpr (std::is_same_v<A, LineStep>) {
    return "Line Step";
  } else if constexpr (std::is_same_v<A, FinishFunction>) {
    return "Finish Function";
  } else if constexpr (std::is_same_v<A, StopImmediately>) {
    return "Stop Immediately";
  } else {
    static_assert(always_false<A>, "Unknown action type");
  }
}

class StopHandler
{
public:
  StopHandler(TraceeController &tc) noexcept;
  virtual ~StopHandler() = default;

  bool has_action_installed(TaskInfo *t) noexcept;
  std::shared_ptr<ThreadProceedAction> get_proceed_action(const TaskInfo &t) noexcept;
  void remove_action(const TaskInfo &t) noexcept;
  void handle_proceed(TaskInfo &info, const tc::ProcessedStopEvent &should_resume) noexcept;

  TraceEvent *prepare_core_from_waitstat(TaskInfo &info) noexcept;
  void set_stop_all() noexcept;
  constexpr void stop_on_clone() noexcept;
  constexpr void stop_on_exec() noexcept;
  constexpr void stop_on_thread_exit() noexcept;

  void SetAndRunAction(Tid tid, std::shared_ptr<ThreadProceedAction>&& action) noexcept;

  TraceeController &tc;

  bool stop_all;
  union
  {
    u8 bitset;
    struct
    {
      bool padding : 3;
      bool clone_stop : 1;
      bool exec_stop : 1;
      bool fork_stop : 1;
      bool thread_exit_stop : 1;
      bool ignore_bps : 1;
    };
  } event_settings;

private:
  // native_ because it's generated from a WaitStatus event (and thus comes directly from ptrace, not a remote)
  TraceEvent *CreateTraceEventFromStopped(TaskInfo &t) noexcept;
  std::unordered_map<Tid, std::shared_ptr<ThreadProceedAction>> proceed_actions;
};

class StepInto final : public ThreadProceedAction
{
  sym::Frame start_frame;
  sym::dw::LineTableEntry starting_line_info;
  bool is_done{false};

public:
  StepInto(TraceeController &ctrl, TaskInfo &task, sym::Frame start_frame, sym::dw::LineTableEntry entry) noexcept;
  ~StepInto() noexcept final;
  bool HasCompleted(bool was_stopped) const noexcept final;
  void Proceed() noexcept final;
  void UpdateStepped() noexcept final;
  bool inside_origin_frame(const sym::Frame &f) const noexcept;
  bool is_origin_line(u32 line) const noexcept;

  static std::shared_ptr<StepInto> create(TraceeController &ctrl, TaskInfo &task) noexcept;
};

} // namespace ptracestop