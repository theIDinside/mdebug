#pragma once

#include "breakpoint.h"
#include "common.h"
#include "interface/dap/dap_defs.h"
#include <symbolication/callstack.h>
#include <symbolication/dwarf/lnp.h>
#include <task.h>
#include <unordered_map>

struct TraceeController;
struct BpStat;

namespace ptracestop {

class StopHandler;

class ThreadProceedAction
{
public:
  ThreadProceedAction(TraceeController &ctrl, TaskInfo &task) noexcept;
  virtual void cancel() noexcept;

  // Abstract Interface
  virtual ~ThreadProceedAction() = default;
  virtual bool has_completed() const noexcept = 0;
  virtual void proceed() noexcept = 0;
  virtual void update_stepped() noexcept = 0;

protected:
  TraceeController &tc;
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
  bool has_completed() const noexcept override;
  void proceed() noexcept override;
  void update_stepped() noexcept override;

private:
  void notify_stopped() noexcept;
  ui::dap::StoppedReason reason;
  bool ptrace_session_is_seize;
};

class InstructionStep : public ThreadProceedAction
{
public:
  InstructionStep(TraceeController &ctrl, TaskInfo &task, int steps) noexcept;
  ~InstructionStep() override;
  bool has_completed() const noexcept override;
  void proceed() noexcept override;
  void update_stepped() noexcept override;

private:
  int steps_requested;
  int steps_taken;
};

class LineStep : public ThreadProceedAction
{
public:
  LineStep(TraceeController &ctrl, TaskInfo &task, int lines) noexcept;
  ~LineStep() noexcept override;
  bool has_completed() const noexcept override;
  void proceed() noexcept override;
  void update_stepped() noexcept override;

private:
  int lines_requested;
  int lines_stepped;
  bool is_done;
  std::optional<AddrPtr> resume_address;
  bool resumed_to_resume_addr;
  sym::Frame start_frame;
  sym::dw::LineTableEntry entry;
};

class FinishFunction : public ThreadProceedAction
{
public:
  FinishFunction(TraceeController &ctrl, TaskInfo &t, Breakpoint *bp, bool should_clean_up) noexcept;
  ~FinishFunction() noexcept override;
  bool has_completed() const noexcept override;
  void proceed() noexcept override;
  void update_stepped() noexcept override;

private:
  Breakpoint *bp;
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
  ThreadProceedAction *get_proceed_action(const TaskInfo &t) noexcept;
  void remove_action(const TaskInfo &t) noexcept;

  void handle_proceed(TaskInfo &info, bool should_resume) noexcept;
  void handle_wait_event(TaskInfo &info) noexcept;
  void set_stop_all() noexcept;
  constexpr void stop_on_clone() noexcept;
  constexpr void stop_on_exec() noexcept;
  constexpr void stop_on_thread_exit() noexcept;

  void set_and_run_action(Tid tid, ThreadProceedAction *action) noexcept;

  TraceeController &tc;

  bool stop_all;
  union
  {
    u8 bitset;
    struct
    {
      bool padding : 4;
      bool clone_stop : 1;
      bool exec_stop : 1;
      bool thread_exit_stop : 1;
      bool ignore_bps : 1;
    };
  } event_settings;

private:
  bool process_waitstatus_for(TaskInfo &t) noexcept;
  std::unordered_map<Tid, ThreadProceedAction *> proceed_actions;
};
} // namespace ptracestop