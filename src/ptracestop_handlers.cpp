#include "ptracestop_handlers.h"
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

namespace ptracestop {
using sym::dw::LineTableEntry;

ThreadProceedAction::ThreadProceedAction(TraceeController &ctrl, TaskInfo &task) noexcept
    : ctrl(ctrl.GetInterface()), tc(ctrl), task(task), cancelled(false)
{
}

void
ThreadProceedAction::cancel() noexcept
{
  cancelled = true;
}

FinishFunction::FinishFunction(TraceeController &ctrl, TaskInfo &t, std::shared_ptr<UserBreakpoint> bp,
                               bool should_clean_up) noexcept
    : ThreadProceedAction(ctrl, t), bp(std::move(bp)), should_cleanup(should_clean_up)
{
}

FinishFunction::~FinishFunction() noexcept
{
  if (!cancelled) {
    task.set_stop();
  }
  tc.RemoveBreakpoint(bp->id);
}

bool
FinishFunction::HasCompleted(bool stopped_by_user) const noexcept
{

  return tc.CacheAndGetPcFor(task) == bp->address() || stopped_by_user;
}

void
FinishFunction::Proceed() noexcept
{
  tc.ResumeTask(task, {tc::RunType::Continue, tc::ResumeTarget::Task});
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
  DBGLOG(core, "[InstructionStep] stepping 1 instruction for {}", task.tid);
  tc.ResumeTask(task, {tc::RunType::Step, tc::ResumeTarget::Task});
}

void
InstructionStep::UpdateStepped() noexcept
{
  ++steps_taken;
}

InstructionStep::~InstructionStep()
{
  if (!cancelled) {
    DBGLOG(core, "[inst step]: instruction step for {} ended", task.tid);
    tc.EmitSteppedStop(LWP{.pid = tc.TaskLeaderTid(), .tid = task.tid}, "Instruction stepping finished", false);
  }
}

LineStep::LineStep(TraceeController &ctrl, TaskInfo &task, int lines) noexcept
    : ThreadProceedAction(ctrl, task), lines_requested(lines), lines_stepped(0), mIsDone(false),
      resumed_to_resume_addr(false), startFrame{nullptr, task, static_cast<u32>(-1), 0, nullptr, nullptr}, entry()
{
  using sym::dw::SourceCodeFile;

  auto &callstack = tc.BuildCallFrameStack(task, CallStackRequest::partial(1));
  // First/bottommost/last/current frame always exists.
  startFrame = *callstack.GetFrameAtLevel(0);
  const auto fpc = startFrame.FramePc();
  SymbolFile *symbolFile = tc.FindObjectByPc(fpc);
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
    DBGLOG(core, "[line step]: line step for {} ended", task.tid);
    EventSystem::Get().PushDebuggerEvent(TraceEvent::SteppingDone({.target = tc.TaskLeaderTid(), .tid = task.tid, .sig_or_code = 0},
                                                "Line stepping finished", {}));
  } else {
    if (resume_bp) {
      tc.RemoveBreakpoint(resume_bp->id);
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
    DBGLOG(core, "[line step]: continuing sub frame for {}", task.tid);
    tc.ResumeTask(task, {tc::RunType::Continue, tc::ResumeTarget::Task});
    resumed_to_resume_addr = true;
  } else {
    DBGLOG(core, "[line step]: no resume address set, keep istepping");
    tc.ResumeTask(task, {tc::RunType::Step, tc::ResumeTarget::Task});
  }
}

void
LineStep::InstallBreakpoint(AddrPtr address) noexcept
{
  resume_bp = tc.GetUserBreakpoints().create_loc_user<ResumeToBreakpoint>(
    tc, tc.GetOrCreateBreakpointLocation(address.as_void()), task.tid, task.tid);
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
  auto frame = tc.GetCurrentFrame(task);
  // if we're in the same frame, we single step

  if (frame.GetFrameType() == sym::FrameType::Full && SameSymbol(frame, startFrame)) {
    ASSERT(frame.FrameLevel() == startFrame.FrameLevel(),
           "We haven't implemented support where recursion actually creates multiple frames that look the same.");
    auto result = frame.GetLineTableEntry();
    const LineTableEntry *lte = result.second;
    MaybeSetDone((!lte || lte->line != entry.line));
  } else {
    auto &callstack = tc.BuildCallFrameStack(task, CallStackRequest::full());
    const auto resumeAddress =
      callstack.FindFrame(startFrame).transform([](const auto &f) -> AddrPtr { return f.FramePc(); });
    if (resumeAddress) {
      InstallBreakpoint(resumeAddress.value());
    } else {
      MaybeSetDone(true);
    }
  }
}

StopHandler::StopHandler(TraceeController &tc) noexcept
    : tc(tc), stop_all(true), event_settings{.bitset = 0x00}, // all OFF by default
      proceed_actions()
{
}

bool
StopHandler::has_action_installed(TaskInfo *t) noexcept
{
  return proceed_actions[t->tid] != nullptr;
}

void
StopHandler::remove_action(const TaskInfo &t) noexcept
{
  ASSERT(proceed_actions.contains(t.tid), "No proceed action installed for {}", t.tid);
  ThreadProceedAction *ptr = proceed_actions[t.tid];
  delete ptr;
  proceed_actions[t.tid] = nullptr;
}

ThreadProceedAction *
StopHandler::get_proceed_action(const TaskInfo &t) noexcept
{
  return proceed_actions[t.tid];
}

void
StopHandler::handle_proceed(TaskInfo &info, const tc::ProcessedStopEvent &stop) noexcept
{
  static_assert(sizeof(tc::ProcessedStopEvent) < 8, "Pass by value so long as it's register-sized");

  auto proceed_action = get_proceed_action(info);
  if (proceed_action) {
    proceed_action->UpdateStepped();
    const auto stopped_by_user = !stop.should_resume;
    if (proceed_action->HasCompleted(stopped_by_user)) {
      remove_action(info);
    } else {
      proceed_action->Proceed();
    }
  } else {
    DBGLOG(core, "[action]: {} will resume (should_resume={}) => {} (pc={})", info.tid, stop.should_resume,
           stop.should_resume && info.can_continue(), info.GetRegisterCache().GetPc());
    const auto kind =
      stop.res.value_or(tc::ResumeAction{.type = tc::RunType::Continue, .target = tc::ResumeTarget::Task});
    bool resumed = false;
    switch (kind.target) {
    case tc::ResumeTarget::Task:
      if (info.can_continue() && stop.should_resume) {
        tc.ResumeTask(info, kind);
        resumed = true;
      } else {
        info.set_stop();
      }
      break;
    case tc::ResumeTarget::AllNonRunningInProcess:
      tc.ResumeTask(kind.type);
      resumed = true;
      break;
    case tc::ResumeTarget::None:
      info.set_stop();
      break;
    }

    if (resumed && tc.IsSessionAllStopMode()) {
      for (auto &t : tc.GetThreads()) {
        t->set_running(kind.type);
      }
    }
  }
}

static TraceEvent *
native_create_clone_event(TraceeController &tc, TaskInfo &cloning_task) noexcept
{
  DBGLOG(core, "Processing CLONE for {}", cloning_task.tid);
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  tc.CacheRegistersFor(cloning_task);
  pid_t np = -1;
  // we should only ever hit this when running debugging a native-hosted session
  ASSERT(tc.GetInterface().format == TargetFormat::Native, "We somehow ended up heer while debugging a remote");
  auto regs = cloning_task.native_registers();
  const auto orig_rax = regs->orig_rax;
  if (orig_rax == SYS_clone) {
    const TPtr<void> stack_ptr = sys_arg_n<2>(*regs);
    const TPtr<int> child_tid = sys_arg_n<4>(*regs);
    const u64 tls = sys_arg_n<5>(*regs);
    np = tc.ReadType(child_tid);

    ASSERT(!tc.HasTask(np), "Tracee controller already has task {} !", np);
    return TraceEvent::CloneEvent({tc.TaskLeaderTid(), cloning_task.tid, 5},
                                 TaskVMInfo{.stack_low = stack_ptr, .stack_size = 0, .tls = tls}, np, {});
  } else if (orig_rax == SYS_clone3) {
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(*regs);
    const auto res = tc.ReadType(ptr);
    np = tc.ReadType(TPtr<pid_t>{res.parent_tid});
    return TraceEvent::CloneEvent({tc.TaskLeaderTid(), cloning_task.tid, 5}, TaskVMInfo::from_clone_args(res), np,
                                 {});
  } else {
    PANIC("Unknown clone syscall!");
  }
}

TraceEvent *
StopHandler::native_core_evt_from_stopped(TaskInfo &t) noexcept
{
  AddrPtr stepped_over_bp_id{nullptr};
  if (t.loc_stat) {
    const auto locstat = t.clear_bpstat();
    return TraceEvent::Stepped({tc.TaskLeaderTid(), t.tid, {}}, !locstat->should_resume, locstat,
                              t.next_resume_action, {});
  }
  const auto pc = tc.CacheAndGetPcFor(t);
  const auto prev_pc_byte = offset(pc, -1);
  auto bp_loc = tc.GetUserBreakpoints().location_at(prev_pc_byte);
  if (bp_loc != nullptr && bp_loc->address() != stepped_over_bp_id) {
    tc.SetProgramCounterFor(t, prev_pc_byte);
    return TraceEvent::SoftwareBreakpointHit({.target = tc.TaskLeaderTid(), .tid = t.tid, .sig_or_code = {}},
                                            prev_pc_byte, {});
  }

  return TraceEvent::DeferToSupervisor({.target = tc.TaskLeaderTid(), .tid = t.tid, .sig_or_code = {}}, {}, false);
}

TraceEvent *
StopHandler::prepare_core_from_waitstat(TaskInfo &info) noexcept
{
  info.set_dirty();
  info.stop_collected = true;
  const auto ws = info.pending_wait_status();
  switch (ws.ws) {
  case WaitStatusKind::Stopped: {
    if (!info.initialized) {
      return TraceEvent::ThreadCreated({tc.TaskLeaderTid(), info.tid, 5},
                                      {tc::RunType::Continue, tc::ResumeTarget::Task}, {});
    }
    return native_core_evt_from_stopped(info);
  }
  case WaitStatusKind::Execed: {
    return TraceEvent::ExecEvent({.target = tc.TaskLeaderTid(), .tid = info.tid, .sig_or_code = 5},
                                process_exe_path(info.tid), {});
  }
  case WaitStatusKind::Exited: {
    // in native mode, only the dying thread is the one that is actually stopped, so we don't have to resume any
    // other threads
    const bool process_needs_resuming = Tracer::Instance->TraceExitConfigured;
    return TraceEvent::ThreadExited({tc.TaskLeaderTid(), info.tid, ws.exit_code}, process_needs_resuming, {});
  }
  case WaitStatusKind::Forked: {
    Tid new_child = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.tid, nullptr, &new_child);
    ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[fork]: new process after fork {}", new_child);
    return TraceEvent::ForkEvent_({tc.TaskLeaderTid(), info.tid, 5}, new_child, {});
  }
  case WaitStatusKind::VForked: {
    Tid new_child = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.tid, nullptr, &new_child);
    ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[vfork]: new process after fork {}", new_child);
    return TraceEvent::VForkEvent_({tc.TaskLeaderTid(), info.tid, 5}, new_child, {});
  }
  case WaitStatusKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case WaitStatusKind::Cloned: {
    return native_create_clone_event(tc, info);
  } break;
  case WaitStatusKind::Signalled:
    return TraceEvent::Signal({tc.TaskLeaderTid(), info.tid, info.wait_status.signal}, {});
  case WaitStatusKind::SyscallEntry:
    TODO("WaitStatusKind::SyscallEntry");
    break;
  case WaitStatusKind::SyscallExit:
    TODO("WaitStatusKind::SyscallExit");
    break;
  case WaitStatusKind::NotKnown:
    TODO("WaitStatusKind::NotKnown");
    break;
  }
  ASSERT(false, "Unknown wait status!");
  MIDAS_UNREACHABLE
}

void
StopHandler::set_stop_all() noexcept
{
  event_settings.bitset = 0xff;
}

constexpr void
StopHandler::stop_on_clone() noexcept
{
  event_settings.clone_stop = true;
}
constexpr void
StopHandler::stop_on_exec() noexcept
{
  event_settings.exec_stop = true;
}
constexpr void
StopHandler::stop_on_thread_exit() noexcept
{
  event_settings.thread_exit_stop = true;
}

void
StopHandler::set_and_run_action(Tid tid, ThreadProceedAction *action) noexcept
{
  ASSERT(proceed_actions[tid] == nullptr,
         "Attempted to set new thread proceed action, without performing cleanup of old");
  proceed_actions[tid] = action;
  action->Proceed();
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
  tc.EmitStopped(task.tid, reason, "stopped", false, {});
}

bool
StopImmediately::HasCompleted(bool) const noexcept
{
  return true;
}

void
StopImmediately::Proceed() noexcept
{
  const auto res = ctrl.StopTask(task);
  if (!res.is_ok()) {
    PANIC(fmt::format("Failed to stop task {}: {}", task.tid, strerror(res.sys_errno)));
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
    EventSystem::Get().PushDebuggerEvent(TraceEvent::SteppingDone({.target = tc.TaskLeaderTid(), .tid = task.tid, .sig_or_code = 0},
                                                "Step in done", {}));
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
  tc.ResumeTask(task, {tc::RunType::Step, tc::ResumeTarget::Task});
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
  auto frame = tc.GetCurrentFrame(task);
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

StepInto *
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
          return new StepInto{ctrl, task, start_frame, *lineTableEntry};
        } else {
          return new StepInto{ctrl, task, start_frame, *(lineTableEntry - 1)};
        }
      }
    }
  }
  return nullptr;
}

} // namespace ptracestop