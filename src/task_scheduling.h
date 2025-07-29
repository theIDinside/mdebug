/** LICENSE TEMPLATE */
#pragma once

#include "bp.h"
#include "interface/dap/dap_defs.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "symbolication/dwarf/lnp.h"
#include "utils/smartptr.h"
#include <symbolication/callstack.h>
#include <unordered_map>

namespace mdb {
class TraceeController;
struct BpStat;
class TaskInfo;
struct TraceEvent;
} // namespace mdb

namespace mdb::tc {
class TraceeCommandInterface;
struct ProcessedStopEvent;
} // namespace mdb::tc

namespace mdb {
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
  TaskInfo &mTask;
  bool mIsCancelled;
};

// A proceed-handler / stop-handler, that stops a task immediately, possibly to perform some one-time task (like
// for instance, notifying an observer)
class StopImmediately : public ThreadProceedAction
{
public:
  StopImmediately(TraceeController &control, TaskInfo &task, ui::dap::StoppedReason reason) noexcept;
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
  InstructionStep(TraceeController &ctrl, TaskInfo &task, int steps) noexcept;
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

  int mRequestedStepCount;
  int mLinesSteppedCount;
  bool mIsDone;
  bool mResumedToReturnAddress;
  sym::Frame mStartFrame;
  sym::dw::LineTableEntry mLineEntry;
  Ref<UserBreakpoint> mPotentialBreakpointAtReturnAddress{nullptr};
};

class FinishFunction : public ThreadProceedAction
{
public:
  FinishFunction(TraceeController &ctrl, TaskInfo &t, Ref<UserBreakpoint> bp, bool should_clean_up) noexcept;
  ~FinishFunction() noexcept override;
  bool HasCompleted(bool was_stopped) const noexcept override;
  void Proceed() noexcept override;
  void UpdateStepped() noexcept override;

private:
  Ref<UserBreakpoint> mBreakpointAtReturnAddress;
  bool mShouldCleanup;
};

class StopHandler
{
public:
  StopHandler(TraceeController &tc) noexcept;
  virtual ~StopHandler() = default;
  std::shared_ptr<ThreadProceedAction> GetProceedAction(const TaskInfo &t) noexcept;
  void RemoveProceedAction(const TaskInfo &t) noexcept;
  void DecideProceedFor(TaskInfo &info, const tc::ProcessedStopEvent &should_resume) noexcept;
  TraceEvent *CreateTraceEventFromWaitStatus(TaskInfo &info) noexcept;

  TraceeController &tc;

private:
  // native_ because it's generated from a WaitStatus event (and thus comes directly from ptrace, not a remote)
  TraceEvent *CreateTraceEventFromStopped(TaskInfo &t) noexcept;
  std::unordered_map<Tid, std::shared_ptr<ThreadProceedAction>> mTaskProceedActions;
};

class StepInto final : public ThreadProceedAction
{
  sym::Frame mStartFrame;
  sym::dw::LineTableEntry mStartingLineEntry;
  bool mIsDone{false};

public:
  StepInto(TraceeController &ctrl, TaskInfo &task, sym::Frame start_frame, sym::dw::LineTableEntry entry) noexcept;
  ~StepInto() noexcept final;
  bool HasCompleted(bool was_stopped) const noexcept final;
  void Proceed() noexcept final;
  void UpdateStepped() noexcept final;
  bool IsInsideOriginFrame(const sym::Frame &f) const noexcept;
  bool IsOriginLine(u32 line) const noexcept;

  static std::shared_ptr<StepInto> Create(TraceeController &ctrl, TaskInfo &task) noexcept;
};

} // namespace ptracestop

using Proceed = ptracestop::ThreadProceedAction;

enum class SchedulingConfig
{
  NormalResume,
  OneExclusive,
  StopAll
};

class TaskScheduler
{
  TraceeController *mSupervisor;
  SchedulingConfig mScheduling;
  std::optional<Tid> mExclusiveTask;
  std::unordered_map<Tid, std::shared_ptr<Proceed>> mIndividualScheduler{};
  void RemoveIndividualScheduler(Tid tid) noexcept;
  void RemoveAllIndividualSchedulers(std::optional<Tid> keep = {}) noexcept;

public:
  TaskScheduler(TraceeController *supervisor) noexcept;
  ~TaskScheduler() noexcept = default;
  bool SetTaskScheduling(Tid tid, std::shared_ptr<Proceed> individualScheduler, bool resume) noexcept;
  void Schedule(TaskInfo &task, tc::ProcessedStopEvent eventProceedResult) noexcept;
  void NormalScheduleTask(TaskInfo &task, tc::ProcessedStopEvent eventProceedResult) noexcept;
  void StopAllScheduleTask(TaskInfo &task) noexcept;

  void SetNormalScheduling() noexcept;
  void SetStopAllScheduling() noexcept;
  void SetOneExclusiveScheduling(Tid tid) noexcept;
};
} // namespace mdb