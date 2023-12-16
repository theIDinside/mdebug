#pragma once

#include "breakpoint.h"
#include "common.h"
#include "symbolication/callstack.h"
#include "symbolication/lnp.h"
#include "task.h"
#include <chrono>
#include <map>
#include <vector>

struct TraceeController;
struct BpStat;

namespace ptracestop {

class StopHandler;

class ThreadProceedAction
{
public:
  ThreadProceedAction(StopHandler *handler, TaskInfo *task) noexcept;
  void cancel() noexcept;

  // Abstract Interface
  virtual ~ThreadProceedAction() = default;
  virtual bool has_completed() const noexcept = 0;
  virtual void proceed() noexcept = 0;
  virtual void update_stepped() noexcept = 0;

protected:
  TraceeController *tc;
  TaskInfo *task;
  bool cancelled;
};

class InstructionStep : public ThreadProceedAction
{
public:
  InstructionStep(StopHandler *handler, TaskInfo *task, int steps) noexcept;
  ~InstructionStep();
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
  LineStep(StopHandler *handler, TaskInfo *task, int lines) noexcept;
  ~LineStep() noexcept;
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
  LineTableEntry entry;
};

template <typename A>
constexpr std::string_view
action_name()
{
  if constexpr (std::is_same_v<A, InstructionStep>) {
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

  bool has_action_installed(TaskInfo *t) noexcept;
  ThreadProceedAction *get_proceed_action(TaskInfo *t) noexcept;
  void remove_action(TaskInfo *t) noexcept;

  void handle_proceed(TaskInfo *info, bool should_resume) noexcept;
  void handle_wait_event(TaskInfo *info) noexcept;
  void set_stop_all() noexcept;
  constexpr void stop_on_clone() noexcept;
  constexpr void stop_on_exec() noexcept;
  constexpr void stop_on_thread_exit() noexcept;

  void set_action(Tid tid, ThreadProceedAction *action) noexcept;

  TraceeController *tc;

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
  bool process_waitstatus_for(TaskInfo *t) noexcept;
  std::map<Tid, ThreadProceedAction *> proceed_actions;
};
} // namespace ptracestop