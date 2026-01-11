/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp.h>
#include <interface/dap/dap_defs.h>
#include <symbolication/dwarf/lnp.h>
#include <utils/smartptr.h>

// std
#include <unordered_map>

namespace mdb {
struct BpStat;
class TaskInfo;
struct TraceEvent;
} // namespace mdb

namespace mdb::tc {
class SupervisorState;
struct ProcessedStopEvent;
} // namespace mdb::tc

namespace mdb::sym {
class Frame;
}

namespace mdb {
namespace ptracestop {

class StopHandler;

class ThreadProceedAction
{
public:
  ThreadProceedAction(tc::SupervisorState &ctrl, TaskInfo &task) noexcept;
  virtual void cancel() noexcept;

  // Abstract Interface
  virtual ~ThreadProceedAction() noexcept = default;
  virtual bool HasCompleted(bool was_stopped) const noexcept = 0;
  virtual void Proceed() noexcept = 0;
  virtual void UpdateStepped() noexcept = 0;

protected:
  tc::SupervisorState &mSupervisor;
  TaskInfo &mTask;
  bool mIsCancelled;
};

// A proceed-handler / stop-handler, that stops a task immediately, possibly to perform some one-time task (like
// for instance, notifying an observer)
class StopImmediately : public ThreadProceedAction
{
public:
  StopImmediately(tc::SupervisorState &control, TaskInfo &task, ui::dap::StoppedReason reason) noexcept;
  ~StopImmediately() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  void NotifyHasStopped() noexcept;
  ui::dap::StoppedReason reason;
};

class InstructionStep : public ThreadProceedAction
{
public:
  InstructionStep(tc::SupervisorState &ctrl, TaskInfo &task, int steps) noexcept;
  ~InstructionStep() override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  int mStepsRequested;
  int mStepsTaken;
};

class LineStep : public ThreadProceedAction
{
  LineStep(tc::SupervisorState &ctrl,
    TaskInfo &task,
    std::unique_ptr<sym::Frame> startFrame,
    sym::dw::LineTableEntry lineTableEntry) noexcept;

public:
  static std::shared_ptr<LineStep> FallibleMake(tc::SupervisorState &ctrl, TaskInfo &task) noexcept;
  ~LineStep() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  // Installs resume-to breakpoint at `address`
  void InstallBreakpoint(AddrPtr address) noexcept;
  void MaybeSetDone(bool isDone) noexcept;

  bool mIsDone;
  bool mResumedToReturnAddress;
  std::unique_ptr<sym::Frame> mStartFrame;
  sym::dw::LineTableEntry mLineEntry;
  Ref<UserBreakpoint> mPotentialBreakpointAtReturnAddress{ nullptr };
};

class FinishFunction : public ThreadProceedAction
{
public:
  FinishFunction(tc::SupervisorState &ctrl, TaskInfo &t, Ref<UserBreakpoint> bp) noexcept;
  ~FinishFunction() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  Ref<UserBreakpoint> mBreakpointAtReturnAddress;
};

class StepInto final : public ThreadProceedAction
{
  sym::Frame *mStartFrame;
  sym::dw::LineTableEntry mStartingLineEntry;
  bool mIsDone{ false };

public:
  StepInto(tc::SupervisorState &ctrl,
    TaskInfo &task,
    const sym::Frame &start_frame,
    sym::dw::LineTableEntry entry) noexcept;
  ~StepInto() noexcept final;
  bool HasCompleted(bool was_stopped) const noexcept final;
  void Proceed() noexcept final;
  void UpdateStepped() noexcept final;
  bool IsInsideOriginFrame(const sym::Frame &f) const noexcept;
  bool IsOriginLine(u32 line) const noexcept;

  static std::shared_ptr<StepInto> Create(tc::SupervisorState &ctrl, TaskInfo &task) noexcept;
};

} // namespace ptracestop

using Proceed = ptracestop::ThreadProceedAction;

enum class SchedulingConfig : u8
{
  NormalResume,
  OneExclusive,
  StopAll
};

class TaskScheduler
{
  tc::SupervisorState *mSupervisor;
  SchedulingConfig mScheduling{ SchedulingConfig::NormalResume };
  std::optional<Tid> mExclusiveTask;
  std::unordered_map<Tid, std::shared_ptr<Proceed>> mIndividualScheduler{};
  void RemoveIndividualScheduler(Tid tid) noexcept;
  void RemoveAllIndividualSchedulers(std::optional<Tid> keep = {}) noexcept;

public:
  TaskScheduler(tc::SupervisorState *supervisor) noexcept;
  ~TaskScheduler() noexcept = default;
  bool SetTaskScheduling(Tid tid, std::shared_ptr<Proceed> individualScheduler, bool resume) noexcept;
  void Schedule(TaskInfo &task, tc::ProcessedStopEvent eventProceedResult) noexcept;
  void ReplaySchedule(TaskInfo &task, tc::ProcessedStopEvent eventProceedResult) noexcept;
  void NormalScheduleTask(TaskInfo &task, bool shouldResume) noexcept;
  void EmitStopWhenAllTasksHalted() noexcept;

  void SetNormalScheduling() noexcept;
  void SetStopAllScheduling() noexcept;
  void SetOneExclusiveScheduling(Tid tid) noexcept;
};
} // namespace mdb