#pragma once

#include "common.h"
#include "task.h"
#include <vector>

struct TraceeController;
class Breakpoint;

namespace ptracestop {
class Action
{
public:
  Action(TraceeController *tc) noexcept : tc(tc), should_stop(false) {}
  virtual ~Action() = default;
  virtual bool
  do_next_action(TaskInfo *t, bool should_stop) noexcept
  {
    constexpr bool is_done = false;
    if (!should_stop) {
      t->set_running(RunType::Continue);
    }
    return is_done;
  }

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

protected:
  TraceeController *tc;
  bool should_stop;
};

class InstructionStep : public Action
{
public:
  InstructionStep(TraceeController *tracee, Tid thread_id, int steps, bool single_thread = false) noexcept;
  ~InstructionStep() override = default;
  virtual bool do_next_action(TaskInfo *t, bool should_stop) noexcept override;
  void start_action() noexcept override;
  bool check_if_done() noexcept override;

private:
  void step_one() noexcept;

protected:
  Tid thread_id;
  int steps;
  bool done;
  std::vector<TaskStepInfo> tsi;
  std::vector<TaskStepInfo>::iterator next;
};

class LineStep final : public InstructionStep
{
public:
  LineStep(TraceeController *tc, Tid thread_id, int lines, bool single_thread = false) noexcept;
  ~LineStep() override final = default;
  void start_action() noexcept override final;
  bool check_if_done() noexcept override final;
};

class StopHandler
{
public:
  StopHandler(TraceeController *tc) noexcept;
  virtual ~StopHandler() = default;

  void handle_execution_event(TaskInfo *t) noexcept;
  void handle_breakpoint_event(TaskInfo *task, Breakpoint *bp) noexcept;
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

  virtual void do_next_action(TaskInfo *t) noexcept;
  void set_action(Action *action) noexcept;
  void restore_default() noexcept;
  void start_action() noexcept;

protected:
  TraceeController *tc;
  Action *action;
  Action *default_action;
  bool should_stop;
  bool stop_all;
  union
  {
    u8 bitset;
    struct
    {
      bool clone_stop : 1;
      bool exec_stop : 1;
      bool thread_exit_stop : 1;
      bool ignore_bps : 1;
    };
  } event_settings;
};
} // namespace ptracestop