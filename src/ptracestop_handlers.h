#pragma once

#include "breakpoint.h"
#include "common.h"
#include "symbolication/callstack.h"
#include "symbolication/lnp.h"
#include "task.h"
#include <chrono>
#include <vector>

struct TraceeController;
class Breakpoint;

namespace ptracestop {

class StopHandler;

class Action
{
public:
  Action(StopHandler *handler) noexcept;
  virtual ~Action() noexcept;

  // `should_stop` is passed in by the StopHandler, if we've encountered
  // an event, signal or whatever, that should abort this installed stepper
  virtual bool do_next_action(TaskInfo *t, bool should_stop) noexcept;

  // default handler does nothing at "start"
  virtual void
  start_action() noexcept
  {
  }

  // default handler is never done
  virtual bool
  check_if_done() noexcept
  {
    return false;
  }

  // Updates the step schedule - this is *not* performed during a ptrace-stop. So no ptrace requests can be made.
  virtual void
  update_step_schedule() noexcept
  {
  }

protected:
  StopHandler *handler;
  TraceeController *tc;
  bool should_stop;
};

class InstructionStep : public Action
{
public:
  InstructionStep(StopHandler *handler, Tid thread_id, int steps, bool single_thread = false) noexcept;
  ~InstructionStep() override = default;
  // `should_stop` is passed in by the StopHandler, if we've encountered
  // an event, signal or whatever, that should abort this installed stepper
  // returns `true` when we _should not continue_
  virtual bool do_next_action(TaskInfo *t, bool should_stop) noexcept override;
  void start_action() noexcept override;
  bool check_if_done() noexcept override;

  // Updates the step schedule - this is *not* performed during a ptrace-stop. So no ptrace requests can be made.
  void update_step_schedule() noexcept override;

protected:
  bool resume() noexcept;
  virtual void resume_impl() noexcept;
  Tid thread_id;
  int steps;
  int debug_steps_taken;
  bool done;
  std::vector<TaskStepInfo> tsi;
  std::vector<TaskStepInfo>::iterator next;
  std::chrono::system_clock::time_point start_time;
};

class LineStep final : public InstructionStep
{
public:
  LineStep(StopHandler *handler, Tid thread_id, int lines, bool single_thread = false) noexcept;
  ~LineStep() noexcept override final;
  void start_action() noexcept override final;
  bool check_if_done() noexcept override final;
  void update_step_schedule() noexcept override final;

  void resume_impl() noexcept override final;

private:
  sym::Frame start_frame;
  LineTableEntry entry;
  const CompilationUnitFile *cu;
  int debug_steps_taken = 0;
  bool resume_address_set;
  AddrPtr resume_addr;
};

template <typename A>
constexpr std::string_view
action_name()
{
  if constexpr (std::is_same_v<A, Action>) {
    return "Default";
  } else if constexpr (std::is_same_v<A, InstructionStep>) {
    return "Instruction Step";
  } else if constexpr (std::is_same_v<A, LineStep>) {
    return "Line Step";
  } else {
    static_assert(always_false<A>, "Unknown action type");
  }
}

class StopHandler
{
public:
  StopHandler(TraceeController *tc) noexcept;
  virtual ~StopHandler() = default;

  void handle_execution_event(TaskInfo *t) noexcept;
  void handle_bp_event(TaskInfo *t, BpEvent evt) noexcept;
  void handle_generic_stop(TaskInfo *t) noexcept;
  void handle_signalled(TaskInfo *t) noexcept;
  void handle_execed(TaskInfo *t) noexcept;
  void handle_exited(TaskInfo *t) noexcept;
  void handle_cloned(TaskInfo *t) noexcept;
  void can_resume() noexcept;
  void set_stop_all() noexcept;
  constexpr void stop_on_clone() noexcept;
  constexpr void stop_on_exec() noexcept;
  constexpr void stop_on_thread_exit() noexcept;
  constexpr void ignore_bps() noexcept;

  void set_action(Action *action) noexcept;
  void restore_default() noexcept;
  void start_action() noexcept;

  TraceeController *tc;
  Action *action;
  Action *default_action;
  bool should_stop;
  bool stop_all;
  std::chrono::high_resolution_clock::time_point prev_time;
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
  bool is_stepping;
};
} // namespace ptracestop