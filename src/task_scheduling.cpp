/** LICENSE TEMPLATE */
#include "task_scheduling.h"
#include "bp.h"
#include "event_queue.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "symbolication/callstack.h"
#include "tracee/util.h"
#include <common.h>
#include <cstring>
#include <events/event.h>
#include <mdbsys/ptrace.h>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/objfile.h>
#include <task.h>
#include <tracer.h>
#include <utility>
namespace mdb {
namespace ptracestop {
using sym::dw::LineTableEntry;

ThreadProceedAction::ThreadProceedAction(TraceeController &ctrl, TaskInfo &task) noexcept
    : mControlInterface(ctrl.GetInterface()), mSupervisor(ctrl), task(task), cancelled(false)
{
}

void
ThreadProceedAction::cancel() noexcept
{
  cancelled = true;
}

FinishFunction::FinishFunction(TraceeController &ctrl, TaskInfo &t, Ref<UserBreakpoint> bp,
                               bool should_clean_up) noexcept
    : ThreadProceedAction(ctrl, t), bp(std::move(bp)), should_cleanup(should_clean_up)
{
}

FinishFunction::~FinishFunction() noexcept
{
  if (!cancelled) {
    task.set_stop();
  }
  mSupervisor.RemoveBreakpoint(bp->mId);
}

bool
FinishFunction::HasCompleted(bool stopped_by_user) const noexcept
{

  return mSupervisor.CacheAndGetPcFor(task) == bp->Address() || stopped_by_user;
}

void
FinishFunction::Proceed() noexcept
{
  mSupervisor.ResumeTask(task, {tc::RunType::Continue, tc::ResumeTarget::Task});
}

void
FinishFunction::UpdateStepped() noexcept
{
  // essentially no-op.
}

InstructionStep::InstructionStep(TraceeController &ctrl, TaskInfo &thread, int steps) noexcept
    : ThreadProceedAction(ctrl, thread), steps_requested(steps), steps_taken(0)
{
}

bool
InstructionStep::HasCompleted(bool stopped_by_user) const noexcept
{
  return steps_taken == steps_requested || stopped_by_user;
}

void
InstructionStep::Proceed() noexcept
{
  DBGLOG(core, "[InstructionStep] stepping 1 instruction for {}", task.mTid);
  mSupervisor.ResumeTask(task, {tc::RunType::Step, tc::ResumeTarget::Task});
}

void
InstructionStep::UpdateStepped() noexcept
{
  ++steps_taken;
}

InstructionStep::~InstructionStep()
{
  if (!cancelled) {
    DBGLOG(core, "[inst step]: instruction step for {} ended", task.mTid);
    mSupervisor.EmitSteppedStop(LWP{.pid = mSupervisor.TaskLeaderTid(), .tid = task.mTid},
                                "Instruction stepping finished", false);
  }
}

LineStep::LineStep(TraceeController &ctrl, TaskInfo &task, int lines) noexcept
    : ThreadProceedAction(ctrl, task), lines_requested(lines), lines_stepped(0), mIsDone(false),
      resumed_to_resume_addr(false), startFrame{nullptr, task, static_cast<u32>(-1), 0, nullptr, nullptr}, entry()
{
  using sym::dw::SourceCodeFile;

  auto &callstack = mSupervisor.BuildCallFrameStack(task, CallStackRequest::partial(1));
  // First/bottommost/last/current frame always exists.
  startFrame = *callstack.GetFrameAtLevel(0);
  const auto fpc = startFrame.FramePc();
  SymbolFile *symbolFile = mSupervisor.FindObjectByPc(fpc);
  ASSERT(symbolFile, "Expected to find a ObjectFile from pc: {}", fpc);

  auto src_infos = symbolFile->GetCompilationUnits(fpc);
  bool found = false;
  const auto unrelocatedPc = symbolFile->UnrelocateAddress(fpc);
  for (auto compilationUnit : src_infos) {

    const auto [sourceCodeFile, lineTableEntry] = compilationUnit->GetLineTableEntry(unrelocatedPc);

    if (sourceCodeFile && lineTableEntry &&
        startFrame.IsInside(lineTableEntry->pc.as_void()) == sym::InsideRange::Yes) {

      if (lineTableEntry->RelocateProgramCounter(symbolFile->mBaseAddress) == fpc) {
        found = true;
        entry = *lineTableEntry;
      } else {
        found = true;
        entry = *(lineTableEntry - 1);
      }
      break;
    }
  }
  VERIFY(found, "Couldn't find Line Table Entry Information needed to navigate source code lines based on pc = {}",
         fpc);
}

LineStep::~LineStep() noexcept
{
  if (!cancelled) {
    DBGLOG(core, "[line step]: line step for {} ended", task.mTid);
    EventSystem::Get().PushDebuggerEvent(TraceEvent::CreateSteppingDone(
      {.target = mSupervisor.TaskLeaderTid(), .tid = task.mTid, .sig_or_code = 0}, "Line stepping finished", {}));
  } else {
    if (resume_bp) {
      mSupervisor.RemoveBreakpoint(resume_bp->mId);
    }
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
  if (resume_bp && !resumed_to_resume_addr) {
    DBGLOG(core, "[line step]: continuing sub frame for {}", task.mTid);
    mSupervisor.ResumeTask(task, {tc::RunType::Continue, tc::ResumeTarget::Task});
    resumed_to_resume_addr = true;
  } else {
    DBGLOG(core, "[line step]: no resume address set, keep istepping");
    mSupervisor.ResumeTask(task, {tc::RunType::Step, tc::ResumeTarget::Task});
  }
}

void
LineStep::InstallBreakpoint(AddrPtr address) noexcept
{
  resume_bp = mSupervisor.GetUserBreakpoints().create_loc_user<ResumeToBreakpoint>(
    mSupervisor, mSupervisor.GetOrCreateBreakpointLocation(address.as_void()), task.mTid, task.mTid);
  resumed_to_resume_addr = false;
}

void
LineStep::MaybeSetDone(bool isDone) noexcept
{
  mIsDone = isDone;
}

void
LineStep::UpdateStepped() noexcept
{
  auto frame = mSupervisor.GetCurrentFrame(task);
  // if we're in the same frame, we single step

  if (frame.GetFrameType() == sym::FrameType::Full && SameSymbol(frame, startFrame)) {
    ASSERT(frame.FrameLevel() == startFrame.FrameLevel(),
           "We haven't implemented support where recursion actually creates multiple frames that look the same.");
    auto result = frame.GetLineTableEntry();
    const LineTableEntry *lte = result.second;
    MaybeSetDone((!lte || lte->line != entry.line));
  } else {
    auto &callstack = mSupervisor.BuildCallFrameStack(task, CallStackRequest::full());
    const auto resumeAddress =
      callstack.FindFrame(startFrame).transform([](const auto &f) -> AddrPtr { return f.FramePc(); });
    if (resumeAddress) {
      InstallBreakpoint(resumeAddress.value());
    } else {
      MaybeSetDone(true);
    }
  }
}

StopImmediately::StopImmediately(TraceeController &ctrl, TaskInfo &task, ui::dap::StoppedReason reason) noexcept
    : ThreadProceedAction(ctrl, task), reason(reason)
{
}

StopImmediately::~StopImmediately() noexcept
{
  if (!cancelled) {
    notify_stopped();
  }
}

void
StopImmediately::notify_stopped() noexcept
{
  task.set_stop();
  mSupervisor.EmitStopped(task.mTid, reason, "stopped", false, {});
}

bool
StopImmediately::HasCompleted(bool) const noexcept
{
  return true;
}

void
StopImmediately::Proceed() noexcept
{
  const auto res = mControlInterface.StopTask(task);
  if (!res.is_ok()) {
    PANIC(fmt::format("Failed to stop task {}: {}", task.mTid, strerror(res.sys_errno)));
  }
}

void
StopImmediately::UpdateStepped() noexcept
{
}

StepInto::StepInto(TraceeController &ctrl, TaskInfo &task, sym::Frame start_frame,
                   sym::dw::LineTableEntry entry) noexcept
    : ThreadProceedAction(ctrl, task), start_frame(start_frame), starting_line_info(entry)
{
}

StepInto::~StepInto() noexcept
{
  if (!cancelled) {
    EventSystem::Get().PushDebuggerEvent(TraceEvent::CreateSteppingDone(
      {.target = mSupervisor.TaskLeaderTid(), .tid = task.mTid, .sig_or_code = 0}, "Step in done", {}));
  }
}

bool
StepInto::HasCompleted(bool stopped_by_user) const noexcept
{
  return is_done || stopped_by_user;
}

void
StepInto::Proceed() noexcept
{
  mSupervisor.ResumeTask(task, {tc::RunType::Step, tc::ResumeTarget::Task});
}

bool
StepInto::is_origin_line(u32 line) const noexcept
{
  return line == starting_line_info.line;
}

bool
StepInto::inside_origin_frame(const sym::Frame &f) const noexcept
{
  return f.GetFrameType() == sym::FrameType::Full && SameSymbol(f, start_frame);
}

void
StepInto::UpdateStepped() noexcept
{
  auto frame = mSupervisor.GetCurrentFrame(task);
  // if we're in the same frame, we single step
  if (inside_origin_frame(frame)) {
    auto result = frame.GetLineTableEntry();
    const LineTableEntry *lte = result.second;
    if (!lte) {
      is_done = true;
    } else if (!is_origin_line(lte->line)) {
      is_done = true;
    }
  } else {
    // means we've left the original frame
    is_done = true;
  }
}

std::shared_ptr<StepInto>
StepInto::create(TraceeController &ctrl, TaskInfo &task) noexcept
{
  auto &callstack = ctrl.BuildCallFrameStack(task, CallStackRequest::partial(1));
  const auto start_frame = *callstack.GetFrameAtLevel(0);
  const auto fpc = start_frame.FramePc();
  SymbolFile *symbol_file = ctrl.FindObjectByPc(fpc);
  ASSERT(symbol_file, "Expected to find a ObjectFile from pc: {}", fpc);

  auto compilationUnits = symbol_file->GetCompilationUnits(fpc);

  for (auto compilationUnit : compilationUnits) {
    const auto [sourceCodeFile, lineTableEntry] =
      compilationUnit->GetLineTableEntry(symbol_file->UnrelocateAddress(fpc));
    if (sourceCodeFile && lineTableEntry) {
      const auto relocPc = lineTableEntry->RelocateProgramCounter(symbol_file->mBaseAddress);
      if (start_frame.IsInside(relocPc) == sym::InsideRange::Yes) {
        if (relocPc == fpc) {
          return std::make_shared<StepInto>(ctrl, task, start_frame, *lineTableEntry);
        } else {
          return std::make_shared<StepInto>(ctrl, task, start_frame, *(lineTableEntry - 1));
        }
      }
    }
  }
  return nullptr;
}

} // namespace ptracestop

TaskScheduler::TaskScheduler(TraceeController *supervisor) noexcept : mSupervisor(supervisor) {}

void
TaskScheduler::RemoveIndividualScheduler(Tid tid) noexcept
{
  mIndividualScheduler.erase(tid);
}

void
TaskScheduler::RemoveAllIndividualSchedulers(std::optional<Tid> keep) noexcept
{
  std::erase_if(mIndividualScheduler, [keep](const auto &a) { return a.first != keep; });
}

bool
TaskScheduler::SetTaskScheduling(Tid tid, std::shared_ptr<Proceed> individualScheduler, bool resume) noexcept
{
  // We're collecting all task stops. We don't allow for new scheduling "algorithms" (until a full-stop has been
  // consumed.)
  switch (mScheduling) {
  case SchedulingConfig::OneExclusive:
    if (tid != mExclusiveTask) {
      return false;
    }
    break;
  case SchedulingConfig::StopAll:
    return false;
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
    NormalScheduleTask(task, eventProceedResult);
    break;
  case SchedulingConfig::StopAll:
    StopAllScheduleTask(task);
    break;
  }
}

void
TaskScheduler::NormalScheduleTask(TaskInfo &task, tc::ProcessedStopEvent eventProceedResult) noexcept
{

  // When a process has exited, or a task has exited, we always proceed the task in the same way (because it's
  // dead, it can't be scheduled at all.)
  if (task.exited || mSupervisor->IsExited()) {
    DBGLOG(core, "{}.{} has exited, process exited={}", mSupervisor->TaskLeaderTid(), task.mTid,
           mSupervisor->IsExited())
    return;
  }

  auto individualScheduler = mIndividualScheduler[task.mTid];
  if (individualScheduler) {
    individualScheduler->UpdateStepped();
    const auto stopped_by_user = !eventProceedResult.should_resume;
    if (individualScheduler->HasCompleted(stopped_by_user)) {
      RemoveIndividualScheduler(task.mTid);
    } else {
      individualScheduler->Proceed();
    }
  } else {
    const auto kind = eventProceedResult.res.value_or(
      tc::ResumeAction{.type = tc::RunType::Continue, .target = tc::ResumeTarget::Task});
    if (task.can_continue() && eventProceedResult.should_resume) {
      mSupervisor->ResumeTask(task, kind);
    } else {
      task.set_stop();
    }
  }
}

void
TaskScheduler::StopAllScheduleTask(TaskInfo &task) noexcept
{
  if (mSupervisor->IsAllStopped()) {
    mSupervisor->EmitAllStopped();
  }
}
} // namespace mdb