/** LICENSE TEMPLATE */
#include "task_scheduling.h"

// mdb
#include <bp.h>
#include <common.h>
#include <event_queue.h>
#include <events/event.h>
#include <mdbsys/ptrace.h>
#include <symbolication/callstack.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/objfile.h>
#include <task.h>
#include <tracee/util.h>
#include <tracer.h>

// std
#include <cstring>
#include <utility>
namespace mdb {
namespace ptracestop {
using sym::dw::LineTableEntry;

ThreadProceedAction::ThreadProceedAction(tc::SupervisorState &ctrl, TaskInfo &task) noexcept
    : mSupervisor(ctrl), mTask(task), mIsCancelled(false)
{
}

void
ThreadProceedAction::cancel() noexcept
{
  DBGLOG(core, "Cancel thread proceed action");
  mIsCancelled = true;
}

FinishFunction::FinishFunction(tc::SupervisorState &ctrl, TaskInfo &t, Ref<UserBreakpoint> bp) noexcept
    : ThreadProceedAction(ctrl, t), mBreakpointAtReturnAddress(std::move(bp))
{
}

FinishFunction::~FinishFunction() noexcept
{
  if (!mIsCancelled) {
    mTask.SetAtTraceEventStop();
  }
  mSupervisor.RemoveBreakpoint(mBreakpointAtReturnAddress->mId);
}

bool
FinishFunction::HasCompleted(bool stopped_by_user) const noexcept
{

  return mSupervisor.CacheAndGetPcFor(mTask) == mBreakpointAtReturnAddress->Address() || stopped_by_user;
}

void
FinishFunction::Proceed() noexcept
{
  mSupervisor.ResumeTask(mTask, tc::RunType::Continue);
}

void
FinishFunction::UpdateStepped() noexcept
{
  // essentially no-op.
}

InstructionStep::InstructionStep(tc::SupervisorState &ctrl, TaskInfo &thread, int steps) noexcept
    : ThreadProceedAction(ctrl, thread), mStepsRequested(steps), mStepsTaken(0)
{
}

bool
InstructionStep::HasCompleted(bool stopped_by_user) const noexcept
{
  return mStepsTaken == mStepsRequested || stopped_by_user;
}

void
InstructionStep::Proceed() noexcept
{
  DBGLOG(core, "[InstructionStep] stepping 1 instruction for {}", mTask.mTid);
  mSupervisor.ResumeTask(mTask, tc::RunType::Step);
}

void
InstructionStep::UpdateStepped() noexcept
{
  ++mStepsTaken;
}

InstructionStep::~InstructionStep()
{
  if (!mIsCancelled) {
    DBGLOG(core, "[inst step]: instruction step for {} ended", mTask.mTid);
    mSupervisor.EmitSteppedStop(
      LWP{ .pid = mSupervisor.TaskLeaderTid(), .tid = mTask.mTid }, "Instruction stepping finished", false);
  }
}

LineStep::LineStep(tc::SupervisorState &ctrl, TaskInfo &task) noexcept
    : ThreadProceedAction(ctrl, task), mIsDone(false), mResumedToReturnAddress(false), mStartFrame{ nullptr },
      mLineEntry()
{
  using sym::dw::SourceCodeFile;

  auto &callstack = mSupervisor.BuildCallFrameStack(task, CallStackRequest::partial(1));
  // First/bottommost/last/current frame always exists.
  mStartFrame = new sym::Frame{ *callstack.GetFrameAtLevel(0) };
  const auto fpc = mStartFrame->FramePc();
  SymbolFile *symbolFile = mSupervisor.FindObjectByPc(fpc);
  MDB_ASSERT(symbolFile, "Expected to find a ObjectFile from pc: {}", fpc);

  auto compilationUnits = symbolFile->GetCompilationUnits(fpc);
  bool found = false;
  const auto unrelocatedPc = symbolFile->UnrelocateAddress(fpc);
  for (auto compilationUnit : compilationUnits) {

    const auto [sourceCodeFile, lineTableEntry] = compilationUnit->GetLineTableEntry(unrelocatedPc);

    if (sourceCodeFile && lineTableEntry &&
        mStartFrame->IsInside(lineTableEntry->pc.AsVoid()) == sym::InsideRange::Yes) {

      if (lineTableEntry->RelocateProgramCounter(symbolFile->mBaseAddress) == fpc) {
        found = true;
        mLineEntry = *lineTableEntry;
      } else {
        found = true;
        mLineEntry = *(lineTableEntry - 1);
      }
      break;
    }
  }
  // TODO: Convert LineStep to instruction stepping, until debug symbol information can be found for RIP
  VERIFY(found,
    "Couldn't find Line Table Entry Information needed to navigate source code lines based on pc = {}",
    fpc);
}

LineStep::~LineStep() noexcept
{
  if (!mIsCancelled) {
    DBGLOG(core, "[line step]: line step for {} ended", mTask.mTid);
    mSupervisor.EmitSteppedStop(
      { .pid = mSupervisor.TaskLeaderTid(), .tid = mTask.mTid }, "Line stepping finished", false);
  }

  if (mPotentialBreakpointAtReturnAddress) {
    mSupervisor.RemoveBreakpoint(mPotentialBreakpointAtReturnAddress->mId);
  }

  if (mStartFrame) {
    delete mStartFrame;
  }
}

bool
LineStep::HasCompleted(bool stopped_by_user) const noexcept
{
  return mIsDone || stopped_by_user;
}

void
LineStep::Proceed() noexcept
{
  if (mPotentialBreakpointAtReturnAddress && !mResumedToReturnAddress) {
    DBGLOG(core, "[line step]: continuing sub frame for {}", mTask.mTid);
    mSupervisor.ResumeTask(mTask, tc::RunType::Continue);
    mResumedToReturnAddress = true;
  } else {
    DBGLOG(core, "[line step]: no resume address set, keep istepping");
    mSupervisor.ResumeTask(mTask, tc::RunType::Step);
  }
}

void
LineStep::InstallBreakpoint(AddrPtr address) noexcept
{
  mPotentialBreakpointAtReturnAddress =
    mSupervisor.GetUserBreakpoints().CreateBreakpointLocationUser<ResumeToBreakpoint>(
      mSupervisor, mSupervisor.GetOrCreateBreakpointLocation(address.AsVoid()), mTask.mTid, mTask.mTid);
  mResumedToReturnAddress = false;
}

void
LineStep::MaybeSetDone(bool isDone) noexcept
{
  DBGLOG(core, "[line step]: Maybe set done to={}", isDone);
  mIsDone = isDone;
}

void
LineStep::UpdateStepped() noexcept
{
  auto frame = mSupervisor.GetCurrentFrame(mTask);
  // if we're in the same frame, we single step

  if (frame.GetFrameType() == sym::FrameType::Full && SameSymbol(frame, *mStartFrame)) {
    MDB_ASSERT(frame.FrameLevel() == mStartFrame->FrameLevel(),
      "We haven't implemented support where recursion actually creates multiple frames that look the same.");
    auto result = frame.GetLineTableEntry();
    const LineTableEntry *lte = result.second;
    DBGLOG(core,
      "[line step]: found Line Table Entry ?={} for pc={}, objfile={}",
      lte != nullptr,
      frame.FramePc(),
      frame.GetSymbolFile()->GetObjectFilePath().c_str());
    MaybeSetDone((!lte || lte->line != mLineEntry.line));
  } else {
    auto &callstack = mSupervisor.BuildCallFrameStack(mTask, CallStackRequest::full());
    const auto resumeAddress =
      callstack.FindFrame(*mStartFrame).transform([](const auto &f) -> AddrPtr { return f.FramePc(); });
    if (resumeAddress) {
      InstallBreakpoint(resumeAddress.value());
    } else {
      MaybeSetDone(true);
    }
  }
}

StopImmediately::StopImmediately(tc::SupervisorState &ctrl, TaskInfo &task, ui::dap::StoppedReason reason) noexcept
    : ThreadProceedAction(ctrl, task), reason(reason)
{
}

StopImmediately::~StopImmediately() noexcept
{
  if (!mIsCancelled) {
    NotifyHasStopped();
  }
}

void
StopImmediately::NotifyHasStopped() noexcept
{
  mTask.SetAtTraceEventStop();
  mSupervisor.EmitStopped(mTask.mTid, reason, "stopped", false, {});
}

bool
StopImmediately::HasCompleted(bool) const noexcept
{
  return true;
}

void
StopImmediately::Proceed() noexcept
{
  const auto res = mSupervisor.StopTask(mTask);
  if (!res.is_ok()) {
    PANIC(std::format("Failed to stop task {}: {}", mTask.mTid, strerror(res.sys_errno)));
  }
}

void
StopImmediately::UpdateStepped() noexcept
{
}

StepInto::StepInto(
  tc::SupervisorState &ctrl, TaskInfo &task, const sym::Frame &start_frame, sym::dw::LineTableEntry entry) noexcept
    : ThreadProceedAction(ctrl, task), mStartFrame(new sym::Frame{ start_frame }), mStartingLineEntry(entry)
{
}

StepInto::~StepInto() noexcept
{
  if (!mIsCancelled) {
    mSupervisor.EmitSteppedStop(
      { .pid = mSupervisor.TaskLeaderTid(), .tid = mTask.mTid }, "Step into command finished.", false);
  }
  if (mStartFrame) {
    delete mStartFrame;
  }
}

bool
StepInto::HasCompleted(bool stopped_by_user) const noexcept
{
  return mIsDone || stopped_by_user;
}

void
StepInto::Proceed() noexcept
{
  mSupervisor.ResumeTask(mTask, tc::RunType::Step);
}

bool
StepInto::IsOriginLine(u32 line) const noexcept
{
  return line == mStartingLineEntry.line;
}

bool
StepInto::IsInsideOriginFrame(const sym::Frame &f) const noexcept
{
  return f.GetFrameType() == sym::FrameType::Full && SameSymbol(f, *mStartFrame);
}

void
StepInto::UpdateStepped() noexcept
{
  auto frame = mSupervisor.GetCurrentFrame(mTask);
  // if we're in the same frame, we single step
  if (IsInsideOriginFrame(frame)) {
    auto result = frame.GetLineTableEntry();
    const LineTableEntry *lte = result.second;
    if (!lte) {
      mIsDone = true;
    } else if (!IsOriginLine(lte->line)) {
      mIsDone = true;
    }
  } else {
    // means we've left the original frame
    mIsDone = true;
  }
}

std::shared_ptr<StepInto>
StepInto::Create(tc::SupervisorState &ctrl, TaskInfo &task) noexcept
{
  auto &callstack = ctrl.BuildCallFrameStack(task, CallStackRequest::partial(1));
  const auto startFrame = *callstack.GetFrameAtLevel(0);
  const auto framePc = startFrame.FramePc();
  SymbolFile *symbolFile = ctrl.FindObjectByPc(framePc);
  MDB_ASSERT(symbolFile, "Expected to find a ObjectFile from pc: {}", framePc);

  auto compilationUnits = symbolFile->GetCompilationUnits(framePc);

  for (auto compilationUnit : compilationUnits) {
    const auto [sourceCodeFile, lineTableEntry] =
      compilationUnit->GetLineTableEntry(symbolFile->UnrelocateAddress(framePc));
    if (sourceCodeFile && lineTableEntry) {
      const auto relocPc = lineTableEntry->RelocateProgramCounter(symbolFile->mBaseAddress);
      if (startFrame.IsInside(relocPc) == sym::InsideRange::Yes) {
        if (relocPc == framePc) {
          return std::make_shared<StepInto>(ctrl, task, startFrame, *lineTableEntry);
        } else {
          return std::make_shared<StepInto>(ctrl, task, startFrame, *(lineTableEntry - 1));
        }
      }
    }
  }
  return nullptr;
}

} // namespace ptracestop

TaskScheduler::TaskScheduler(tc::SupervisorState *supervisor) noexcept : mSupervisor(supervisor) {}

void
TaskScheduler::RemoveIndividualScheduler(Tid tid) noexcept
{
  DBGLOG(core, "Removing scheduler for {}", tid);
  mIndividualScheduler.erase(tid);
}

void
TaskScheduler::RemoveAllIndividualSchedulers(std::optional<Tid> keep) noexcept
{
  std::erase_if(mIndividualScheduler, [keep](const auto &a) {
    auto &[tid, scheduler] = a;
    if (tid != keep && scheduler != nullptr) {
      scheduler->cancel();
      return true;
    }
    return false;
  });
}

bool
TaskScheduler::SetTaskScheduling(Tid tid, std::shared_ptr<Proceed> individualScheduler, bool resume) noexcept
{
  // We're collecting all task stops. We don't allow for new scheduling "algorithms" (until a full-stop has been
  // consumed.)
  switch (mScheduling) {
  case SchedulingConfig::OneExclusive:
    if (tid != mExclusiveTask) {
      individualScheduler->cancel();
      return false;
    }
    break;
  case SchedulingConfig::StopAll: {
    individualScheduler->cancel();
    return false;
  }
  case SchedulingConfig::NormalResume:
    break;
  }

  mIndividualScheduler[tid] = std::move(individualScheduler);
  if (resume) {
    mIndividualScheduler[tid]->Proceed();
  }

  return true;
}

void
TaskScheduler::SetNormalScheduling() noexcept
{
  mScheduling = SchedulingConfig::NormalResume;
}

void
TaskScheduler::SetStopAllScheduling() noexcept
{
  RemoveAllIndividualSchedulers();
  mScheduling = SchedulingConfig::StopAll;
}

void
TaskScheduler::SetOneExclusiveScheduling(Tid tid) noexcept
{
  RemoveAllIndividualSchedulers(tid);
  mExclusiveTask = tid;
  mScheduling = SchedulingConfig::OneExclusive;
}

void
TaskScheduler::Schedule(TaskInfo &task, tc::ProcessedStopEvent eventProceedResult) noexcept
{
  switch (mScheduling) {
  case SchedulingConfig::OneExclusive:
    if (task.mTid != mExclusiveTask) {
      break;
    }
    [[fallthrough]];
  case SchedulingConfig::NormalResume:
    NormalScheduleTask(task, eventProceedResult.mShouldResumeAfterProcessing);
    break;
  case SchedulingConfig::StopAll:
    EmitStopWhenAllTasksHalted();
    break;
  }
}

void
TaskScheduler::NormalScheduleTask(TaskInfo &task, bool shouldResume) noexcept
{
  // When a process has exited, or a task has exited, we always proceed the task in the same way (because it's
  // dead, it can't be scheduled at all.)
  if (task.mExited || mSupervisor->IsExited()) {
    DBGLOG(core,
      "{}.{} has exited, process exited={}",
      mSupervisor->TaskLeaderTid(),
      task.mTid,
      mSupervisor->IsExited())
    return;
  }

  auto individualScheduler = mIndividualScheduler[task.mTid];
  if (individualScheduler) {
    DBGLOG(core, "Task has individual scheduler");
    individualScheduler->UpdateStepped();
    const auto stoppedByUser = !shouldResume;
    if (individualScheduler->HasCompleted(stoppedByUser)) {
      DBGLOG(core, "remove scheduler for {}, stopped by user={}", task.mTid, stoppedByUser);
      RemoveIndividualScheduler(task.mTid);
    } else {
      individualScheduler->Proceed();
    }
  } else {
    if (task.CanContinue() && shouldResume) {
      mSupervisor->ResumeTask(task, task.mResumeRequest.mType);
    } else {
      task.SetAtTraceEventStop();
    }
  }
}

void
TaskScheduler::EmitStopWhenAllTasksHalted() noexcept
{
  if (mSupervisor->IsAllStopped()) {
    mSupervisor->EmitAllStopped();
    SetNormalScheduling();
  }
}
} // namespace mdb