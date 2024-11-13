#include "ptracestop_handlers.h"
#include "bp.h"
#include "event_queue.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "symbolication/callstack.h"
#include "tracee/util.h"
#include <common.h>
#include <cstring>
#include <events/event.h>
#include <ptrace.h>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/objfile.h>
#include <sys/ptrace.h>
#include <task.h>
#include <tracer.h>

namespace ptracestop {

ThreadProceedAction::ThreadProceedAction(TraceeController &ctrl, TaskInfo &task) noexcept
    : ctrl(ctrl.get_interface()), tc(ctrl), task(task), cancelled(false)
{
}

void
ThreadProceedAction::cancel() noexcept
{
  cancelled = true;
}

FinishFunction::FinishFunction(TraceeController &ctrl, TaskInfo &t, std::shared_ptr<UserBreakpoint> bp,
                               bool should_clean_up) noexcept
    : ThreadProceedAction(ctrl, t), bp(bp), should_cleanup(should_clean_up)
{
}

FinishFunction::~FinishFunction() noexcept { tc.remove_breakpoint(bp->id); }

bool
FinishFunction::has_completed(bool stopped_by_user) const noexcept
{

  return tc.get_caching_pc(task) == bp->address() || stopped_by_user;
}

void
FinishFunction::proceed() noexcept
{
  tc.resume_task(task, {tc::RunType::Continue, tc::ResumeTarget::Task});
}

void
FinishFunction::update_stepped() noexcept
{
  // essentially no-op.
}

InstructionStep::InstructionStep(TraceeController &ctrl, TaskInfo &thread, int steps) noexcept
    : ThreadProceedAction(ctrl, thread), steps_requested(steps), steps_taken(0)
{
}

bool
InstructionStep::has_completed(bool stopped_by_user) const noexcept
{
  return steps_taken == steps_requested || stopped_by_user;
}

void
InstructionStep::proceed() noexcept
{
  DBGLOG(core, "[InstructionStep] stepping 1 instruction for {}", task.tid);
  tc.resume_task(task, {tc::RunType::Step, tc::ResumeTarget::Task});
}

void
InstructionStep::update_stepped() noexcept
{
  ++steps_taken;
}

InstructionStep::~InstructionStep()
{
  if (!cancelled) {
    DBGLOG(core, "[inst step]: instruction step for {} ended", task.tid);
    tc.emit_stepped_stop(LWP{.pid = tc.get_task_leader(), .tid = task.tid}, "Instruction stepping finished",
                         false);
  }
}

LineStep::LineStep(TraceeController &ctrl, TaskInfo &task, int lines) noexcept
    : ThreadProceedAction(ctrl, task), lines_requested(lines), lines_stepped(0), is_done(false),
      resumed_to_resume_addr(false), start_frame{nullptr, task, static_cast<u32>(-1), 0, nullptr, nullptr}, entry()
{
  auto &callstack = tc.build_callframe_stack(task, CallStackRequest::partial(1));
  // First/bottommost/last/current frame always exists.
  start_frame = *callstack.GetFrameAtLevel(0);
  const auto fpc = start_frame.pc();
  SymbolFile *symbol_file = tc.find_obj_by_pc(fpc);
  ASSERT(symbol_file, "Expected to find a ObjectFile from pc: {}", fpc);

  auto src_infos = symbol_file->getSourceInfos(fpc);
  bool found = false;

  // the std::unordered_set here is just for de-duplication.
  std::vector<sym::dw::RelocatedSourceCodeFile> files_of_interest{};
  for (auto src : src_infos) {
    auto files = src->sources();

    for (const auto &f : files) {
      if (utils::none_of(files_of_interest, [&f](auto &file) { return f->full_path == file.path(); })) {
        files_of_interest.push_back(sym::dw::RelocatedSourceCodeFile{symbol_file->baseAddress, f});
      }
    }
  }

  for (auto &&file : files_of_interest) {
    if (auto it = file.find_lte_by_pc(fpc); it) {
      auto lte = it.transform([](auto it) { return it.get(); });
      if (start_frame.inside(lte->pc.as_void()) == sym::InsideRange::Yes) {
        if (lte->pc == fpc) {
          found = true;
          entry = *lte;
          break;
        } else {
          found = true;
          entry = (it.value() - 1).get();
          break;
        }
      }
    }
  }
  VERIFY(found, "Couldn't find Line Table Entry Information needed to navigate source code lines based on pc = {}",
         fpc);
}

LineStep::~LineStep() noexcept
{
  if (!cancelled) {
    DBGLOG(core, "[line step]: line step for {} ended", task.tid);
    push_debugger_event(CoreEvent::SteppingDone(
      {.target = tc.get_task_leader(), .tid = task.tid, .sig_or_code = 0}, "Line stepping finished", {}));
  } else {
    if (resume_bp) {
      tc.remove_breakpoint(resume_bp->id);
    }
  }
}

bool
LineStep::has_completed(bool stopped_by_user) const noexcept
{
  return is_done || stopped_by_user;
}

void
LineStep::proceed() noexcept
{
  if (resume_bp && !resumed_to_resume_addr) {
    DBGLOG(core, "[line step]: continuing sub frame for {}", task.tid);
    tc.resume_task(task, {tc::RunType::Continue, tc::ResumeTarget::Task});
    resumed_to_resume_addr = true;
  } else {
    DBGLOG(core, "[line step]: no resume address set, keep istepping");
    tc.resume_task(task, {tc::RunType::Step, tc::ResumeTarget::Task});
  }
}

void
LineStep::update_stepped() noexcept
{
  const auto frame = tc.current_frame(task);
  // if we're in the same frame, we single step

  if (frame.frame_type() == sym::FrameType::Full && same_symbol(frame, start_frame)) {
    ASSERT(frame.level() == start_frame.level(),
           "We haven't implemented support where recursion actually creates multiple frames that look the same.");
    auto lt = frame.cu_line_table();
    if (!lt) {
      is_done = true;
      return;
    }
    const auto fpc = frame.pc();
    auto lte = lt->find_by_pc(fpc);
    if (lte == lt->end()) {
      is_done = true;
    }
    if (fpc < lte.get().pc && fpc > (lte - 1).get().pc) {
      return;
    }
    if ((*lte).line != entry.line) {
      is_done = true;
    }
  } else {
    auto &callstack = tc.build_callframe_stack(task, CallStackRequest::full());
    const auto resumeAddress =
      callstack.FindFrame(start_frame).transform([](const auto &f) -> AddrPtr { return f.pc(); });
    if (resumeAddress) {
      resume_bp = tc.user_breakpoints().create_loc_user<ResumeToBreakpoint>(
        tc, tc.get_or_create_bp_location(resumeAddress->as_void(), false), task.tid, task.tid);
    } else {
      TODO_FMT("Could not determine resume address using start frame {}; haven't implemented line step in "
               "recursive functions or in the case where some function below does a longjmp and possible entirely "
               "invalidates the callstack.",
               start_frame);
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
StopHandler::handle_proceed(TaskInfo &info, const tc::ProcessedStopEvent& stop) noexcept
{
  static_assert(sizeof(tc::ProcessedStopEvent) < 8, "Pass by value so long as it's register-sized");

  auto proceed_action = get_proceed_action(info);
  if (proceed_action) {
    proceed_action->update_stepped();
    const auto stopped_by_user = !stop.should_resume;
    if (proceed_action->has_completed(stopped_by_user)) {
      remove_action(info);
    } else {
      proceed_action->proceed();
    }
  } else {
    DBGLOG(core, "[action]: {} will resume (should_resume={}) => {}", info.tid, stop.should_resume,
           stop.should_resume && info.can_continue());
    const auto kind =
      stop.res.value_or(tc::ResumeAction{.type = tc::RunType::Continue, .target = tc::ResumeTarget::Task});
    bool resumed = false;
    switch (kind.target) {
    case tc::ResumeTarget::Task:
      if (info.can_continue() && stop.should_resume) {
        tc.resume_task(info, kind);
        resumed = true;
      } else {
        info.set_stop();
      }
      break;
    case tc::ResumeTarget::AllNonRunningInProcess:
      tc.resume_target(kind.type);
      resumed = true;
      break;
    case tc::ResumeTarget::None:
      info.set_stop();
      break;
    }

    if (resumed && tc.session_all_stop_mode()) {
      for (auto &t : tc.get_threads()) {
        t->set_running(kind.type);
      }
    }
  }
}

static CoreEvent *
native_create_clone_event(TraceeController &tc, TaskInfo &cloning_task) noexcept
{
  DBGLOG(core, "Processing CLONE for {}", cloning_task.tid);
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  tc.cache_registers(cloning_task);
  pid_t np = -1;
  // we should only ever hit this when running debugging a native-hosted session
  ASSERT(tc.get_interface().format == TargetFormat::Native, "We somehow ended up heer while debugging a remote");
  auto regs = cloning_task.native_registers();
  const auto orig_rax = regs->orig_rax;
  if (orig_rax == SYS_clone) {
    const TPtr<void> stack_ptr = sys_arg_n<2>(*regs);
    const TPtr<int> child_tid = sys_arg_n<4>(*regs);
    const u64 tls = sys_arg_n<5>(*regs);
    np = tc.read_type(child_tid);

    ASSERT(!tc.has_task(np), "Tracee controller already has task {} !", np);
    return CoreEvent::CloneEvent({tc.get_task_leader(), cloning_task.tid, 5},
                                 TaskVMInfo{.stack_low = stack_ptr, .stack_size = 0, .tls = tls}, np, {});
  } else if (orig_rax == SYS_clone3) {
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(*regs);
    const auto res = tc.read_type(ptr);
    np = tc.read_type(TPtr<pid_t>{res.parent_tid});
    return CoreEvent::CloneEvent({tc.get_task_leader(), cloning_task.tid, 5}, TaskVMInfo::from_clone_args(res), np,
                                 {});
  } else {
    PANIC("Unknown clone syscall!");
  }
}

CoreEvent *
StopHandler::native_core_evt_from_stopped(TaskInfo &t) noexcept
{
  AddrPtr stepped_over_bp_id{nullptr};
  if (t.loc_stat) {
    const auto locstat = t.clear_bpstat();
    return CoreEvent::Stepped({tc.get_task_leader(), t.tid, {}}, !locstat->should_resume, locstat,
                              std::move(t.next_resume_action), {});
  }
  const auto pc = tc.get_caching_pc(t);
  const auto prev_pc_byte = offset(pc, -1);
  auto bp_loc = tc.user_breakpoints().location_at(prev_pc_byte);
  if (bp_loc != nullptr && bp_loc->address() != stepped_over_bp_id) {
    tc.set_pc(t, prev_pc_byte);
    return CoreEvent::SoftwareBreakpointHit({.target = tc.get_task_leader(), .tid = t.tid, .sig_or_code = {}},
                                            prev_pc_byte, {});
  }

  return CoreEvent::DeferToSupervisor({.target = tc.get_task_leader(), .tid = t.tid, .sig_or_code = {}}, {},
                                      false);
}

CoreEvent *
StopHandler::prepare_core_from_waitstat(TaskInfo &info) noexcept
{
  info.set_dirty();
  info.stop_collected = true;
  const auto ws = info.pending_wait_status();
  switch (ws.ws) {
  case WaitStatusKind::Stopped: {
    if (!info.initialized) {
      return CoreEvent::ThreadCreated({tc.get_task_leader(), info.tid, 5},
                                      {tc::RunType::Continue, tc::ResumeTarget::Task}, {});
    }
    if (tc.is_on_entry()) {
      return CoreEvent::EntryEvent({tc.get_task_leader(), info.tid, 5}, {}, true);
    }
    return native_core_evt_from_stopped(info);
  }
  case WaitStatusKind::Execed: {
    return CoreEvent::ExecEvent({.target = tc.get_task_leader(), .tid = info.tid, .sig_or_code = 5},
                                process_exe_path(info.tid), {});
  }
  case WaitStatusKind::Exited: {
    // in native mode, only the dying thread is the one that is actually stopped, so we don't have to resume any
    // other threads
    const bool process_needs_resuming = Tracer::Instance->TraceExitConfigured;
    return CoreEvent::ThreadExited({tc.get_task_leader(), info.tid, ws.exit_code}, process_needs_resuming, {});
  }
  case WaitStatusKind::Forked: {
    Tid new_child = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.tid, nullptr, &new_child);
    ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[fork]: new process after fork {}", new_child);
    return CoreEvent::ForkEvent({tc.get_task_leader(), info.tid, 5}, new_child, {});
  }
  case WaitStatusKind::VForked:
    TODO("WaitStatusKind::VForked");
    break;
  case WaitStatusKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case WaitStatusKind::Cloned: {
    return native_create_clone_event(tc, info);
  } break;
  case WaitStatusKind::Signalled:
    return CoreEvent::Signal({tc.get_task_leader(), info.tid, info.wait_status.signal}, {});
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
  action->proceed();
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
  tc.emit_stopped(task.tid, reason, "stopped", false, {});
}

bool
StopImmediately::has_completed(bool) const noexcept
{
  return true;
}

void
StopImmediately::proceed() noexcept
{
  const auto res = ctrl.stop_task(task);
  if (!res.is_ok()) {
    PANIC(fmt::format("Failed to stop task {}: {}", task.tid, strerror(res.sys_errno)));
  }
}

void
StopImmediately::update_stepped() noexcept
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
    push_debugger_event(CoreEvent::SteppingDone(
      {.target = tc.get_task_leader(), .tid = task.tid, .sig_or_code = 0}, "Step in done", {}));
  }
}

bool
StepInto::has_completed(bool stopped_by_user) const noexcept
{
  return is_done || stopped_by_user;
}

void
StepInto::proceed() noexcept
{
  tc.resume_task(task, {tc::RunType::Step, tc::ResumeTarget::Task});
}

bool
StepInto::is_origin_line(u32 line) const noexcept
{
  return line == starting_line_info.line;
}

bool
StepInto::inside_origin_frame(const sym::Frame &f) const noexcept
{
  return f.frame_type() == sym::FrameType::Full && same_symbol(f, start_frame);
}

void
StepInto::update_stepped() noexcept
{
  const auto frame = tc.current_frame(task);
  // if we're in the same frame, we single step
  if (inside_origin_frame(frame)) {
    auto lt = frame.cu_line_table();
    if (!lt) {
      is_done = true;
      return;
    }
    const auto fpc = frame.pc();
    auto lte = lt->find_by_pc(fpc);
    // we could no longer find LTE; which probably means we've left our origin line.
    if (lte == lt->end()) {
      is_done = true;
      return;
    }
    if (fpc < lte.get().pc && fpc > (lte - 1).get().pc) {
      return;
    }
    if (!is_origin_line(lte.get().line)) {
      is_done = true;
      return;
    }
  } else {
    // means we've left the original frame
    is_done = true;
  }
}

StepInto *
StepInto::create(TraceeController &ctrl, TaskInfo &task) noexcept
{
  auto &callstack = ctrl.build_callframe_stack(task, CallStackRequest::partial(1));
  const auto start_frame = *callstack.GetFrameAtLevel(0);
  const auto fpc = start_frame.pc();
  SymbolFile *symbol_file = ctrl.find_obj_by_pc(fpc);
  ASSERT(symbol_file, "Expected to find a ObjectFile from pc: {}", fpc);

  auto src_infos = symbol_file->getSourceInfos(fpc);

  // the std::unordered_set here is just for de-duplication.
  std::vector<sym::dw::RelocatedSourceCodeFile> files_of_interest{};
  for (auto src : src_infos) {
    auto files = src->sources();

    for (const auto &f : files) {
      if (utils::none_of(files_of_interest, [&f](auto &file) { return f->full_path == file.path(); })) {
        files_of_interest.push_back(sym::dw::RelocatedSourceCodeFile{symbol_file->baseAddress, f});
      }
    }
  }

  for (auto &&file : files_of_interest) {
    if (auto it = file.find_lte_by_pc(fpc); it) {
      auto lte = it->get();
      if (start_frame.inside(lte.pc.as_void()) == sym::InsideRange::Yes) {
        if (lte.pc == fpc) {
          return new StepInto{ctrl, task, start_frame, lte};
        } else {
          return new StepInto{ctrl, task, start_frame, (it.value() - 1).get()};
        }
      }
    }
  }
  return nullptr;
}

} // namespace ptracestop