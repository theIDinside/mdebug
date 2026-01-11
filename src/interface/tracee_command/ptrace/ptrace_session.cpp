/** LICENSE TEMPLATE */
#include "ptrace_session.h"
#include "common.h"
#include "interface/tracee_command/request_results.h"
#include "tracee/util.h"
#include "utils/logger.h"
#include "utils/util.h"

// mdb
#include <elf.h>
#include <interface/dap/events.h>
#include <interface/pty.h>
#include <interface/tracee_command/supervisor_state.h>
#include <link.h>
#include <mdbsys/ptrace.h>
#include <mdbsys/stop_status.h>
#include <memory_resource>
#include <sys/personality.h>
#include <task.h>
#include <utils/todo.h>

// std
#include <cstdlib>

// system
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

namespace mdb::tc::ptrace {

std::vector<PtraceEvent> Session::sUnhandledPtraceEvents = {};

// WIFSTOPPED   == true => IfStoppedToStopStatus
// WIFEXITED    == true => IfExitedToStopStatus
// WIFSIGNALED  == true => IfSignalledToStopStatus

static __ptrace_request
ToPtrace(RunType runtype)
{
  switch (runtype) {
  case RunType::Unknown:
    PANIC("Invalid ptrace resume type");
    break;
  case RunType::Step:
    return PTRACE_SINGLESTEP;
  case RunType::Continue:
    return PTRACE_CONT;
  case RunType::SyscallContinue:
    return PTRACE_SYSCALL;
  }
}

static StopStatus
IfSignalledToStopStatus(PtraceEvent event) noexcept
{
  return StopStatus{
    .ws = StopKind::Signalled, .mIsTerminatingEvent = true, .mPid = event.mPid, .uSignal = WSTOPSIG(event.mStatus)
  };
}

static StopStatus
IfExitedToStopStatus(PtraceEvent event) noexcept
{
  return StopStatus{ .ws = StopKind::Exited,
    .mIsTerminatingEvent = true,
    .mPid = event.mPid,
    .uExitCode = WEXITSTATUS(event.mStatus) };
}

static StopStatus
IfStoppedToStopStatus(PtraceEvent event) noexcept
{
  using enum StopKind;
  const auto signal = WSTOPSIG(event.mStatus);
  StopStatus result{ .mPid = event.mPid };
  result.mIsTerminatingEvent = false;
  auto &kind = result.ws;

  if (IS_SYSCALL_SIGTRAP(signal)) {
    PtraceSyscallInfo info;
    constexpr auto size = sizeof(PtraceSyscallInfo);
    PTRACE_OR_PANIC(PTRACE_GET_SYSCALL_INFO, event.mPid, size, &info);
    if (info.IsEntry()) {
      kind = SyscallEntry;
    } else {
      kind = SyscallExit;
    }
  } else if (IS_TRACE_EVENT(event.mStatus, PTRACE_EVENT_CLONE)) {
    kind = Cloned;
  } else if (IS_TRACE_EVENT(event.mStatus, PTRACE_EVENT_EXEC)) {
    kind = Execed;
  } else if (IS_TRACE_EVENT(event.mStatus, PTRACE_EVENT_EXIT)) {
    kind = Exited;
  } else if (IS_TRACE_EVENT(event.mStatus, PTRACE_EVENT_FORK)) {
    kind = Forked;
  } else if (IS_TRACE_EVENT(event.mStatus, PTRACE_EVENT_VFORK)) {
    kind = VForked;
  } else if (IS_TRACE_EVENT(event.mStatus, PTRACE_EVENT_VFORK_DONE)) {
    kind = VForkDone;
  } else {
    if (signal == SIGTRAP) {
      kind = Stopped;
    } else if (signal == SIGSTOP) {
      kind = Stopped;
    } else {
      kind = Signalled;
      result.uSignal = signal;
    }
  }
  return result;
}

static StopStatus
PtraceEventToStopStatus(PtraceEvent event) noexcept
{
  if (WIFSTOPPED(event.mStatus)) {
    return IfStoppedToStopStatus(event);
  } else if (WIFEXITED(event.mStatus)) {
    return IfExitedToStopStatus(event);
  } else if (WIFSIGNALED(event.mStatus)) {
    return IfSignalledToStopStatus(event);
  }
  PANIC("Should never reach here.");
};

bool
RegisterCache::Refresh() noexcept
{
  if (const auto ptrace_result = ::ptrace(PTRACE_GETREGS, mTid, nullptr, &mUser); ptrace_result == -1) {
    return false;
  }
  return true;
}

void
Session::HandleEvent(TaskInfo &task, PtraceEvent event) noexcept
{
  const auto stopStatus = PtraceEventToStopStatus(event);

  switch (mStopEventHandlerStack.ProcessEvent(stopStatus)) {
  case EventState::Unhandled: {
    HandleEvent(task, stopStatus);
  } break;
  case EventState::Handled: {
  } break;
  case EventState::Defer: {
    QueuePending(stopStatus);
  } break;
  }
}

/* static */
void
Session::QueueUnhandledPtraceEvent(PtraceEvent event) noexcept
{
  DBGLOG(core,
    "Queueing ptrace event for {}. Potentially received out of order from clone event in parent.",
    event.mPid);
  sUnhandledPtraceEvents.push_back(event);
}

void
Session::ProcessQueuedUnhandled(Pid childPid) noexcept
{
  auto it = std::ranges::find_if(
    sUnhandledPtraceEvents, [tid = childPid](const PtraceEvent &event) { return event.mPid == tid; });
  if (it != std::end(sUnhandledPtraceEvents)) {
    DBGBUFLOG(core, "processing queued event for {}", childPid);
    PtraceEvent e = *it;
    sUnhandledPtraceEvents.erase(it);
    auto task = GetTaskByTid(childPid);
    VERIFY(task,
      "Task should have been created & initialized at this point, dealing with out-of-order creation/clone "
      "events.");
    HandleEvent(*task, e);
  }
}

TaskExecuteResponse
Session::ReadRegisters(TaskInfo &t) noexcept
{
  RegisterCache &cache = mRegisterCache[t.mTid];
  bool success = cache.Refresh();
  t.mRegisterCacheDirty = !success;
  if (success) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(errno);
}

TaskExecuteResponse
Session::WriteRegisters(TaskInfo &t, void *data, size_t length) noexcept
{
  TODO("Process::WriteRegisters(TaskInfo &t, void *data, size_t length) noexcept");
}

TaskExecuteResponse
Session::SetRegister(TaskInfo &t, size_t registerNumber, void *data, size_t length) noexcept
{
  TODO("Process::SetRegister(TaskInfo &t, size_t registerNumber, void *data, size_t length) noexcept");
}
// Used for normal debugging operations. Retrieving special registers is uninteresting from a debugger interface
// perspective and as such should be handled specifically. For instance, unwinding the stack which is a very
// common operation, relies solely on user registers and never anything else. locations of types and objects, are
// defined by DWARF operations and these also, never use special registers. If this changes, just change this
// interface to account for special registers as well.
u64
Session::GetUserRegister(const TaskInfo &t, size_t registerNumber) noexcept
{
  auto &cache = mRegisterCache[t.mTid];
  return get_register(&cache.mUser, registerNumber);
}

TaskExecuteResponse
Session::DoDisconnect(bool terminate) noexcept
{
  if (terminate && !IsExited()) {
    // PostTaskExit mutates mThreads (invalidates iterators)
    std::vector<TaskInfo *> tasks;
    TransformCopyTo(mThreads, tasks, [](const auto &entry) { return entry.mTask.Get(); });
    for (auto task : tasks) {
      // Do we even care about this? It probably should be up to linux to handle it for us if there's an error
      // here.
      const auto _ = tgkill(mTaskLeader, task->mTid, SIGKILL);
      PostTaskExit(*task, /* notify */ true);
    }
  } else if (!IsExited()) {
    StopAllTasks();
    for (auto &user : mUserBreakpoints.AllUserBreakpoints()) {
      mUserBreakpoints.RemoveUserBreakpoint(user->mId);
    }
    for (auto &entry : mThreads) {
      // Do we even care about this? It probably should be up to linux to handle it for us if there's an error
      // here.
      auto res = ::ptrace(PTRACE_DETACH, entry.mTid, nullptr, nullptr);
      MDB_ASSERT(res != -1, "Failed to detach from {}", entry.mTid);
    }
  }
  PerformShutdown();
  return TaskExecuteResponse::Ok();
}

ReadResult
Session::DoReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept
{
  auto readBytes = pread64(mProcFsMemFd.Get(), read_buffer, size, address.GetRaw());
  if (readBytes > 0) {
    return ReadResult::Ok(static_cast<u32>(readBytes));
  } else if (readBytes == 0) {
    return ReadResult::EoF();
  } else {
    return ReadResult::SystemError(errno);
  }
}

TraceeWriteResult
Session::DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept
{
  const auto result = pwrite64(mProcFsMemFd.Get(), buf, size, addr.GetRaw());
  if (result > 0) {
    return TraceeWriteResult::Ok(static_cast<u32>(result));
  } else {
    return TraceeWriteResult::Error(errno);
  }
}

bool
Session::PerformShutdown() noexcept
{
  return true;
}

// Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
// that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
TaskExecuteResponse
Session::InstallBreakpoint(Tid tid, AddrPtr addr) noexcept
{
  constexpr u64 bkpt = 0xcc;
  const auto read_value = ::ptrace(PTRACE_PEEKDATA, tid, addr.GetRaw(), nullptr);
  if (read_value == -1) {
    DBGBUFLOG(control, "instructions at {} contains 0x{:x}", addr, read_value);
  }

  const u64 installed_bp = ((read_value & ~0xff) | bkpt);
  DBGBUFLOG(control, "writing instructions at {} to 0x{:x}", addr, installed_bp);
  if (const auto res = ::ptrace(PTRACE_POKEDATA, tid, addr.GetRaw(), installed_bp); res == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  const u8 originalByte = static_cast<u8>(read_value & 0xff);
  return TaskExecuteResponse::Ok(originalByte);
}

TaskExecuteResponse
Session::EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  MDB_ASSERT(HasTask(tid), "This supervisor does not have thread {}", tid);
  DBGBUFLOG(control, "[{}.{}:bkpt]: enabling breakpoint at {}", TaskLeaderTid(), tid, location.Address());
  return InstallBreakpoint(tid, location.Address());
}

TaskExecuteResponse
Session::DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  MDB_ASSERT(HasTask(tid), "This supervisor does not have thread {}", tid);
  DBGBUFLOG(control, "[{}.{}:bkpt]: disabling breakpoint at {}", TaskLeaderTid(), tid, location.Address());

  const auto addrParam = location.Address().GetRaw();
  const auto read_value = ::ptrace(PTRACE_PEEKDATA, tid, addrParam, nullptr);
  if (read_value == -1) {
    DBGBUFLOG(control, "failed to read instructions at {}", addrParam);
    return TaskExecuteResponse::Error(errno);
  }

  const u8 original_byte = location.mOriginalByte;
  const u64 restore = ((read_value & ~0xff) | original_byte);

  if (auto res = ::ptrace(PTRACE_POKEDATA, tid, addrParam, restore); res == -1) {
    DBGBUFLOG(control, "failed to write instructions 0x{:x} at {}", restore, addrParam);
    return TaskExecuteResponse::Error(errno);
  }

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
Session::StopTask(TaskInfo &t) noexcept
{
  const auto result = tgkill(mTaskLeader, t.mTid, SIGSTOP);
  if (result == -1) {
    DBGBUFLOG(control, "failed to send SIGSTOP to {}.{}", mTaskLeader, t.mTid);
    return TaskExecuteResponse::Error(errno);
  }
  DBGBUFLOG(control, "sent SIGSTOP to {}.{}", mTaskLeader, t.mTid);
  t.RequestedStop();
  return TaskExecuteResponse::Ok();
}

void
Session::DoResumeTask(TaskInfo &t, RunType runType) noexcept
{
  MDB_ASSERT(t.mTraceeState > TraceeState::Running, "Attempted to resume task that was running");
  if (t.mTraceeState > TraceeState::Running) {
    const auto signal = t.ConsumeSignal();
    DBGBUFLOG(
      control, "[{}.{}] resuming with {} with signal {}", TaskLeaderTid(), t.mTid, runType, signal.value_or(0));
    const auto ptrace_result = ::ptrace(ToPtrace(runType), t.mTid, nullptr, signal.value_or(0));
    if (ptrace_result == -1) {
      // Reset the last pending signal, to be sent later
      if (signal) {
        t.SetSignalToForward(*signal);
      }
      DBGBUFLOG(control, "[WARNING]: failed to resume {}: {}", t.mTid, strerror(errno));
      return;
    }
  } else {
    DBGBUFLOG(control, "[{}.{}]: Did not resume, not recorded signal delivery stop.", mTaskLeader, t.mTid);
  }
  t.SetIsRunning();
}

bool
Session::DoResumeTarget(RunType type) noexcept
{
  u32 resumed = 0;
  for (auto &t : mThreads) {
    if (t.mTask->CanContinue()) {
      mScheduler->Schedule(*t.mTask, { true });
      if (!t.mTask->CanContinue()) {
        resumed++;
      }
    }
  }
  return resumed > 0;
}

void
Session::AttachSession(ui::dap::DebugAdapterSession &session) noexcept
{
  session.OnCreatedSupervisor(NonNull<tc::SupervisorState>(*this));
  OnConfigurationDone([](tc::SupervisorState *supervisor) {
    mdb::tc::ptrace::Session *process = static_cast<mdb::tc::ptrace::Session *>(supervisor);
    process->ProcessDeferredEvents();
    process->ProcessQueuedUnhandled(process->TaskLeaderTid());
    return true;
  });
}

bool
Session::Pause(Tid tid) noexcept
{
  auto task = GetTaskByTid(tid);
  if (task->IsStopped()) {
    return false;
  }
  const bool success = SetAndCallRunAction(
    task->mTid, std::make_shared<ptracestop::StopImmediately>(*this, *task, ui::dap::StoppedReason::Pause));
  return success;
}

void
Session::SetProgramCounterTo(TaskInfo &task, AddrPtr addr) noexcept
{
  constexpr auto ripOffset = offsetof(user_regs_struct, rip);
  const auto ptraceResult = ::ptrace(PTRACE_POKEUSER, task.mTid, ripOffset, addr.GetRaw());
  VERIFY(ptraceResult != -1, "ptrace failed: {}", strerror(errno));
  auto &cache = mRegisterCache[task.mTid];
  cache.mUser.rip = addr;
}

Session::Session(Tid taskLeader, ui::dap::DebugAdapterManager *dap) noexcept
    : SupervisorState(SupervisorType::Native, taskLeader, dap)
{
}

void
Session::OpenMemoryFile() noexcept
{
  if (mProcFsMemFd.IsOpen()) {
    mProcFsMemFd.Close();
  }
  MDB_ASSERT(!mProcFsMemFd.IsOpen(), "MemFd already open");
  const auto procMemFdPath = std::format("/proc/{}/task/{}/mem", mTaskLeader, mTaskLeader);
  mProcFsMemFd = mdb::ScopedFd::Open(procMemFdPath, O_RDWR);
  MDB_ASSERT(mProcFsMemFd.IsOpen(), "Failed to open proc mem fs for {}", mTaskLeader);
}

RegisterCache *
Session::GetUpToDateRegisterCache(Tid tid) noexcept
{
  auto task = GetTaskByTid(tid);
  VERIFY(task, "Expected task {} to exist", tid);
  if (task->mRegisterCacheDirty) {
    CacheRegistersFor(*task, false);
  }
  return &mRegisterCache[tid];
}

/* static */
std::vector<Elf64_Phdr>
Session::LoadProgramHeaders(Pid pid, AddrPtr phdrAddress, size_t phdrCount, size_t phdrEntrySize) noexcept
{
  std::vector<Elf64_Phdr> result{ phdrCount };
  for (auto i = 0; i < phdrCount; ++i) {
    auto entryAddress = phdrAddress + i * phdrEntrySize;
    auto &entry = result.emplace_back();
    const auto readResult = DoReadBytes(entryAddress, sizeof(Elf64_Phdr), (u8 *)&entry);
    MDB_ASSERT(readResult.WasSuccessful() && readResult.uBytesRead == phdrEntrySize, "Read not of expected size");
  }
  return result;
}

static int
Exec(const Path &program, std::span<const std::pmr::string> programArguments, char **env)
{
  const auto arg_size = programArguments.size() + 2;
  std::vector<const char *> args;
  args.resize(arg_size, nullptr);
  const char *cmd = program.c_str();
  args[0] = cmd;
  auto idx = 1;
  for (const auto &arg : programArguments) {
    args[idx++] = arg.c_str();
  }
  // environ = env;
  args[arg_size - 1] = nullptr;
  return execve(cmd, (char *const *)args.data(), env);
}

static void
ConfigurePtraceSettings(pid_t pid)
{
  // PTRACE_O_TRACEEXIT stops on exit of a task, but it's not at a point where we can do anything. At which point
  // my question becomes: what's the purpose? I'd rather just be notified that a task has died and that's that.
  const auto options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD |
                       PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT;
  if (-1 == ::ptrace(PTRACE_SETOPTIONS, pid, 0, options)) {
    int stat;
    if (-1 == waitpid(pid, &stat, 0)) {
      perror("failed to set new target & options");
      PANIC("Exiting");
    }
    if (-1 == ::ptrace(PTRACE_SETOPTIONS, pid, 0, options)) {
      PANIC(std::format("Failed to set PTRACE options for {}: {}", pid, strerror(errno)));
    }
  }
}

Session *
Session::ForkExec(ui::dap::DebugAdapterManager *debugAdapterClient,
  SessionId sessionId,
  bool stopAtEntry,
  const Path &program,
  std::span<std::pmr::string> prog_args,
  std::optional<BreakpointBehavior> breakpointBehavior) noexcept
{
  termios originalTty;
  winsize ws;

  bool couldSetTermSettings = (tcgetattr(STDIN_FILENO, &originalTty) != -1);
  if (couldSetTermSettings) {
    VERIFY(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0, "Failed to get winsize of stdin");
  }

  std::vector<std::string> execvpArgs{};
  execvpArgs.push_back(program.c_str());
  for (const auto &arg : prog_args) {
    execvpArgs.push_back(std::string{ arg });
  }

  std::vector<char *> environment;
  for (auto i = 0; environ[i] != nullptr; ++i) {
    environment.push_back(environ[i]);
  }

  environment.push_back(nullptr);
  for (const auto *env : environment) {
    if (env != nullptr) {
      DBGLOG(core, "env={}", env);
    }
  }

  // We wait until the last minute to start blocking SIGCHLD, because there may be sessions where we don't want to
  // interfere (at all) with these things on the main thread specifically for RR, at least until I know exactly
  // what the effects would be.
  EventSystem::Get().InitWaitStatusManager();

  const auto forkResult =
    ptyFork(false, couldSetTermSettings ? &originalTty : nullptr, couldSetTermSettings ? &ws : nullptr);
  // todo(simon): we're forking our already big Tracer process, just to tear it down and exec a new process
  //  I'd much rather like a "stub" process to exec from, that gets handed to us by some "Fork server" thing,
  //  but the logic for that is way more complex and I'm not really interested in solving that problem right now.
  switch (forkResult.index()) {
  case 0: // child
  {
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
      PANIC("Failed to set ADDR_NO_RANDOMIZE!");
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL; // Set handler to default action

    // Loop over all signals from 1 to 31
    for (int i = 1; i <= 31; ++i) {
      // Avoid resetting signals that can't be caught or ignored
      if (i == SIGKILL || i == SIGSTOP) {
        continue;
      }
      VERIFY(sigaction(i, &sa, nullptr) == 0, "Expected to succeed to reset signal handler for signal {}", i);
    }

    PTRACE_OR_PANIC(PTRACE_TRACEME, 0, 0, 0);

    if (Exec(program, prog_args, environment.data()) == -1) {
      PANIC(std::format("EXECV Failed for {}", program.c_str()));
    }
    _exit(0);
    break;
  }
  default: {
    pid_t childPid = 0;
    std::optional<int> ttyFd = std::nullopt;
    if (forkResult.index() == 1) {
      const auto res = get<PtyParentResult>(forkResult);
      childPid = res.mPid;
      ttyFd = res.mFd;
    } else {
      const auto res = get<ParentResult>(forkResult);
      childPid = res.mChildPid;
    }

    const auto leader = childPid;

    ConfigurePtraceSettings(leader);
    auto supervisor = Session::Create(sessionId, leader, debugAdapterClient);
    supervisor->OpenMemoryFile();

    debugAdapterClient->SetDebugAdapterSessionType(ui::dap::DapClientSession::Launch);
    supervisor->ConfigureBreakpointBehavior(
      breakpointBehavior.value_or(BreakpointBehavior::StopAllThreadsWhenHit));

    std::string threadName;
    auto name = supervisor->ReadThreadName(leader, threadName);
    supervisor->CreateNewTask(leader, threadName, false);

    supervisor->PostExec(program, stopAtEntry, /* installDynamicLoaderBreakpoints */ true);

    if (ttyFd) {
      debugAdapterClient->SetTtyOut(*ttyFd, supervisor->GetSessionId());
    }

    return supervisor;
  }
  }
}

/* static */
Session *
Session::Create(std::optional<SessionId> sessionId, Tid taskLeader, ui::dap::DebugAdapterManager *dap) noexcept
{
  auto supervisor = std::unique_ptr<Session>(new Session{ taskLeader, dap });
  auto ptr = supervisor.get();

  if (sessionId) {
    Tracer::GetDebugAdapterManager().InitializeSession(*sessionId);
    auto session = Tracer::GetDebugAdapterManager().GetSession(*sessionId);
    session->OnCreatedSupervisor(NonNull<tc::SupervisorState>(*ptr));
  }

  Tracer::AddSupervisor(std::move(supervisor));
  return ptr;
}

static inline Pid
NativeInitCloneEvent(TaskInfo &cloningTask, const user_regs_struct &regs, Session &control) noexcept
{
  DBGLOG(core, "Processing CLONE for {}", cloningTask.mTid);

  // TODO: Make use of this once bugs and issues are resolve enough for this to be interesting.
  const auto orig_rax = regs.orig_rax;
  if (orig_rax == SYS_clone) {
    const TPtr<void> pointerToStackPointerArg = sys_arg_n<2>(regs);
    const TPtr<int> pointerToChildTidArg = sys_arg_n<4>(regs);
    const u64 tls = sys_arg_n<5>(regs);
    auto childPid = control.ReadType(pointerToChildTidArg);
    // result.mTaskVMInfo = vmInfo;
    MDB_ASSERT(!control.HasTask(childPid), "Tracee controller already has task {} !", childPid);
    return childPid;
  } else if (orig_rax == SYS_clone3) {
    const TraceePointer<clone_args> ptr = sys_arg<mdb::SysRegister::RDI>(regs);
    const auto res = control.ReadType(ptr);
    const auto childPid = control.ReadType(TPtr<pid_t>{ res.parent_tid });
    // result.mTaskVMInfo = TaskVMInfo{ .stack_low = res.stack, .stack_size = res.stack_size, .tls = res.tls };
    return childPid;
  }
  PANIC("Unknown clone syscall!");
}

void
Session::HandleEvent(TaskInfo &task, StopStatus stopStatus) noexcept
{
  task.SetAtTraceEventStop();
  task.SetValueLiveness(Tracer::Get().GetCurrentVariableReferenceBoundary());

  if (stopStatus.mIsTerminatingEvent) {
    DBGBUFLOG(core, "stop event is tracee-termination.");
  }

  bool steppedOverBreakpoint = false;

  if (task.mBreakpointLocationStatus.mBreakpointLocation && task.mBreakpointLocationStatus.mIsSteppingOver) {
    steppedOverBreakpoint = true;
    task.mBreakpointLocationStatus.mBreakpointLocation->Enable(task.mTid, *this);
    // Clear breakpoint location status. The existence of this value, means the task needs to step over a
    // breakpoint. Since we've established that we've stepped over one here, we need to clear the loc status, so
    // that the next resume doesn't think it needs stepping over a breakpoint.
    task.ClearBreakpointLocStatus();
  }

  switch (stopStatus.ws) {
  case StopKind::Stopped: {
    if (!task.mHasStarted) {
      mDebugAdapterClient->PostDapEvent(
        new ui::dap::ThreadEvent{ mSessionId, ui::dap::ThreadReason::Started, task.mTid });
      task.mHasStarted = true;
      mScheduler->Schedule(task, { true, task.mResumeRequest.mType });
    } else {

      const auto breakpointAdjustedProgramCounter = offset(CacheAndGetPcFor(task), -1);
      RefPtr breakpointLocation = mUserBreakpoints.GetLocationAt(breakpointAdjustedProgramCounter);
      if (breakpointLocation != nullptr && !steppedOverBreakpoint) {
        SetProgramCounterTo(task, breakpointAdjustedProgramCounter);
        HandleBreakpointHit(task, breakpointLocation);
      } else {
        // Uninteresting (to us) stop, or couldn't figure out if we do need stopping. Schedule whatever is
        // queued.
        mScheduler->Schedule(task, { true, task.mResumeRequest.mType });
      }
    }
  } break;
  case StopKind::Execed: {
    OpenMemoryFile();
    const auto execFile = ProcessExecPath(task.mTid);
    HandleExec(task, execFile);
  } break;
  case StopKind::Exited: {
    DBGBUFLOG(core,
      "Exit code for thread {} exited={}, terminating event={}",
      task.mTid,
      stopStatus.uExitCode,
      stopStatus.mIsTerminatingEvent);
    if (!task.mExited) {
      PostTaskExit(task, !task.mExited);
    }

    if (!stopStatus.mIsTerminatingEvent) {
      task.mReaped = true;
      const auto ptrace_result = ::ptrace(PTRACE_CONT, task.mTid, nullptr, 0);
      if (ptrace_result == -1) {
        DBGBUFLOG(control, "Failed to resume task.");
      }
    } else {
      if (mThreads.empty()) {
        mDebugAdapterClient->PostDapEvent(new ui::dap::ExitedEvent{ mSessionId, stopStatus.uSignal });
        ShutDownDebugAdapterClient();
        mIsExited = true;
        Tracer::Get().OnDisconnectOrExit(this);
      }
    }
  } break;
  case StopKind::Forked:
    [[fallthrough]];
  case StopKind::VForked: {
    Tid childPid = 0;
    auto result = ::ptrace(PTRACE_GETEVENTMSG, task.mTid, nullptr, &childPid);
    MDB_ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[v|fork]: new process after fork {}", childPid);
    HandleFork(task, childPid, stopStatus.ws == StopKind::VForked);
  } break;
  case StopKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case StopKind::Cloned: {
    auto childPid = NativeInitCloneEvent(task, GetUpToDateRegisterCache(task.mTid)->mUser, *this);
    std::string threadName;
    if (!ReadThreadName(childPid, threadName) && !ReadThreadName(mTaskLeader, threadName)) {
      threadName = "???";
    }
    CreateNewTask(childPid, threadName, false);
    mScheduler->Schedule(task, { true, task.mResumeRequest.mType });
    ProcessQueuedUnhandled(childPid);
  } break;
  case StopKind::Signalled: {
    if (stopStatus.mIsTerminatingEvent) {
      // TODO: Allow signals through / stop process / etc. Allow for configurability here.
      DBGLOG(core, "Terminated by signal: {}", stopStatus.uSignal);
      mDebugAdapterClient->PostDapEvent(new ui::dap::ExitedEvent{ mSessionId, stopStatus.uSignal });
      ShutDownDebugAdapterClient();
      mIsExited = true;
    } else {
      task.SetSignalToForward(stopStatus.uSignal);
      mScheduler->Schedule(task, { true, task.mResumeRequest.mType });
    }
  } break;
  case StopKind::SyscallEntry:
    TODO("WaitStatusKind::SyscallEntry");
    break;
  case StopKind::SyscallExit:
    TODO("WaitStatusKind::SyscallExit");
    break;
  case StopKind::NotKnown:
    TODO("WaitStatusKind::NotKnown");
    break;
  }
}

void
Session::QueuePending(StopStatus event) noexcept
{
  mDeferredEvents.push_back(event);
}

void
Session::ProcessDeferredEvents() noexcept
{
  mStopEventHandlerStack.Pop();
  for (auto e : mDeferredEvents) {
    auto task = GetTaskByTid(e.mPid);
    HandleEvent(*task, e);
  }
}

bool
Session::ReadThreadName(Tid tid, std::string &result) noexcept
{
  std::array<char, 256> pathbuf{};

  auto it = std::format_to(pathbuf.begin(), "/proc/{}/task/{}/comm", TaskLeaderTid(), tid);
  std::string_view path{ pathbuf.data(), it };
  auto file = mdb::ScopedFd::OpenFileReadOnly(path);

  std::array<char, 16> tmp{};
  auto len = ::read(file, tmp.data(), 16);

  if (len == -1) {
    const auto res = std::to_chars(tmp.data(), tmp.data() + 16, tid);
    if (res.ec != std::errc()) {
      return false;
    }
    len = static_cast<u32>(res.ptr - tmp.data());
  }

  for (const auto &ch : tmp) {
    if (ch == 0 || ch == '\n') {
      break;
    }
    result.push_back(ch);
  }

  return true;
}

void
Session::HandleFork(TaskInfo &parentTask, pid_t childPid, bool vFork) noexcept
{
  auto newSupervisor = Session::Create(std::nullopt, childPid, mDebugAdapterClient);

  bool resume = true;
  if (!vFork) {
    DBGLOG(core, "event was not vfork; disabling breakpoints in new address space.");

    newSupervisor->OnForkFrom(*this);
    // the new process space copies the old one; which contains breakpoints.
    // we restore the newly forked process space to the real contents. New breakpoints will be set
    // by the initialize -> configDone sequence
    Set<AddrPtr> uninstalledBreakpointLocations{};
    for (const auto &user : GetUserBreakpoints().AllUserBreakpoints()) {
      if (auto loc = user->GetLocation(); loc && !uninstalledBreakpointLocations.contains(loc->Address())) {
        newSupervisor->DisableBreakpoint(newSupervisor->mTaskLeader, *loc);
        uninstalledBreakpointLocations.insert(loc->Address());
      }
    }
    newSupervisor->mStopEventHandlerStack.PushEventHandler([](auto &e) { return EventState::Defer; });
    newSupervisor->OpenMemoryFile();

    mDebugAdapterClient->PostDapEvent(new ui::dap::Process{ mSessionId, childPid, "forked", true });
    mScheduler->Schedule(parentTask, { true && resume, parentTask.mResumeRequest.mType });
  } else {
    // under no circumstances are we allowed to resume the parent while the vfork-to-exec is in flight.
    mStopEventHandlerStack.PushEventHandler([](const auto &) { return EventState::Defer; });
    newSupervisor->mIsVForking = true;
    newSupervisor->GetOnExecOrExitPublisher().Once(
      [parent = this, self = newSupervisor, task = RefPtr{ &parentTask }, newPid = childPid]() {
        parent->ProcessDeferredEvents();
        self->mIsVForking = false;
        parent->mDebugAdapterClient->PostDapEvent(
          new ui::dap::Process{ parent->mSessionId, newPid, "forked", true });
        parent->ScheduleResume(*task, tc::RunType::Continue);
      });
  }
}

mdb::Expected<Auxv, Error>
Session::DoReadAuxiliaryVector() noexcept
{
  const auto path = std::format("/proc/{}/auxv", TaskLeaderTid());
  DBGLOG(core, "Reading auxv for {} at {}", TaskLeaderTid(), path);
  mdb::ScopedFd procfile = mdb::ScopedFd::OpenFileReadOnly(path);
  // we can read 256 elements at a time (id + value = u64 * 2)
  static constexpr auto Count = 512;
  auto offset = 0;
  u64 buffer[Count];
  Auxv res;
  while (true) {
    const auto result = pread(procfile, buffer, sizeof(u64) * Count, offset);
    if (result == -1) {
      return Error{ .mSysErrorNumber = errno, .mErrorMessage = strerror(errno) };
    }
    MDB_ASSERT(result > (8 * 2),
      "Expected to read at least 1 element (last element should always be a 0, 0 pair, "
      "thus one element should always exist at the minimum) but read {}",
      result);
    const auto item_count = result / 8;

    res.mContents.reserve(res.mContents.size() + item_count);
    for (auto i = 0u; i < item_count; i += 2) {
      if (buffer[i] == 0 && buffer[i + 1] == 0) {
        return res;
      }
      res.mContents.emplace_back(buffer[i], buffer[i + 1]);
    }
    std::memset(buffer, 0, sizeof(u64) * Count);
    offset += sizeof(u64) * Count;
  }
}

void
Session::InitRegisterCacheFor(const TaskInfo &task) noexcept
{
  MDB_ASSERT(!mRegisterCache.contains(task.mTid), "Register cache already created");
  auto &cache = mRegisterCache[task.mTid];
  cache.mTid = task.mTid;
}
} // namespace mdb::tc::ptrace