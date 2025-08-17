/** LICENSE TEMPLATE */
// mdb
#include "tracer.h"
#include "common/typedefs.h"
#include <bp.h>
#include <event_queue.h>
#include <interface/attach_args.h>
#include <interface/console_command.h>
#include <interface/dap/dap_defs.h>
#include <interface/dap/events.h>
#include <interface/dap/interface.h>
#include <interface/pty.h>
#include <interface/remotegdb/connection.h>
#include <interface/tracee_command/ptrace_commander.h>
#include <lib/arena_allocator.h>
#include <lib/lockguard.h>
#include <lib/spinlock.h>
#include <lib/stack.h>
#include <mdbjs/mdbjs.h>
#include <supervisor.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <sys/ptrace.h>
#include <task.h>
#include <task_scheduling.h>
#include <utils/expected.h>
#include <utils/logger.h>
#include <utils/scope_defer.h>
#include <utils/scoped_fd.h>
#include <utils/thread_pool.h>

#include <quickjs/quickjs.h>

// stdlib
#include <algorithm>
#include <utility>

// system
#include <dirent.h>
#include <fcntl.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <unistd.h>

namespace mdb {

Tracer::Tracer(sys::DebuggerConfiguration init) noexcept : config(std::move(init))
{
  ASSERT(Tracer::sTracerInstance == nullptr,
    "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
    (uintptr_t)this,
    (uintptr_t)sTracerInstance);
  mConsoleCommandInterpreter = new ConsoleCommandInterpreter{};
}

void
Tracer::LoadAndProcessObjectFile(pid_t target_pid, const Path &objfile_path) noexcept
{
  // TODO(simon) Once "shared object symbols" (NOT to be confused with Linux' shared objects/so's!) is implemented
  //  we should check if the object file from `objfile_path` has already been loaded into memory
  auto target = GetController(target_pid);
  if (auto symbol_obj = Tracer::Get().LookupSymbolfile(objfile_path); symbol_obj == nullptr) {
    auto obj = ObjectFile::CreateObjectFile(target, objfile_path);
    target->RegisterObjectFile(target, std::move(obj), true, nullptr);
  } else {
    target->RegisterSymbolFile(symbol_obj, true);
  }
}

// static
Tracer *
Tracer::Create(sys::DebuggerConfiguration cfg) noexcept
{
  sTracerInstance = new Tracer{ std::move(cfg) };
  return sTracerInstance;
}

/* static */
bool
Tracer::IsRunning() noexcept
{
  return sApplicationState == TracerProcess::Running;
}

/* static */
bool
Tracer::UsingTraceMe() noexcept
{
  return sUsePTraceMe;
}

// static
Tracer &
Tracer::Get() noexcept
{
  return *sTracerInstance;
}

/* static */
TraceeController *
Tracer::PrepareNewSupervisorWithId(SessionId sessionId) noexcept
{
  static SessionId latestSessionId = 0;
  ASSERT(sessionId > latestSessionId, "Preparing a new session with a previously used ID is not supported.");
  latestSessionId = sessionId;
  auto &instance = Tracer::Get();
  instance.mUnInitializedSupervisor.push_back(
    std::make_pair(sessionId, TraceeController::CreateDetached(sessionId)));
  return instance.mUnInitializedSupervisor.back().second.get();
}

void
Tracer::TerminateSession() noexcept
{
  for (auto &t : mTracedProcesses) {
    t->GetInterface().DoDisconnect(true);
    t->GetPublisher(ObserverType::AllStop).Once([sv = t.get()]() {
      EventSystem::Get().PushInternalEvent(InvalidateSupervisor{ sv });
    });
  }
  EventSystem::Get().PushInternalEvent(TerminateDebugging{});
}

void
Tracer::AddLaunchedTarget(SessionId sessionId, const tc::InterfaceConfig &config, TargetSession session) noexcept
{
  std::unique_ptr<TraceeController> preparedSupervisor{ nullptr };
  auto it = find_if(mUnInitializedSupervisor, [&](const auto &info) { return info.first == sessionId; });
  VERIFY(it.has_value(), "Failed to find prepared supervisor with id {}", sessionId);

  std::unique_ptr supervisor = std::move(it.value()->second);
  supervisor->InitializeSupervisor(
    session, tc::TraceeCommandInterface::CreateCommandInterface(config), InterfaceType::Ptrace);
  mTracedProcesses.push_back(std::move(supervisor));

  const auto newProcess = mTracedProcesses.back()->GetInterface().TaskLeaderTid();

  if (!Tracer::sUsePTraceMe) {
    PTRACE_OR_PANIC(PTRACE_ATTACH, newProcess, 0, 0);
  }
  ConfigurePtraceSettings(newProcess);
  EventSystem::Get().InitWaitStatusManager();
}

TraceeController *
Tracer::GetProcessContainingTid(Tid tid) noexcept
{
  for (auto &t : mTracedProcesses) {
    if (t->GetTaskByTid(tid)) {
      return t.get();
    }
  }
  return nullptr;
}

TraceeController *
Tracer::GetController(pid_t pid) noexcept
{
  auto it = std::ranges::find_if(mTracedProcesses, [&pid](auto &t) { return t->mTaskLeader == pid; });
  ASSERT(it != std::end(mTracedProcesses), "Could not find target {} pid", pid);

  return it->get();
}

Ref<TaskInfo>
Tracer::TakeUninitializedTask(Tid tid) noexcept
{
  if (mUnInitializedThreads.contains(tid)) {
    auto t = std::move(mUnInitializedThreads[tid]);
    mUnInitializedThreads.erase(tid);
    return t;
  }
  return nullptr;
}

TraceEvent *
Tracer::ConvertWaitEvent(WaitPidResult waitPid) noexcept
{
  auto tc = GetProcessContainingTid(waitPid.tid);
  if (!tc) {
    DBGLOG(core, "Task {} left unitialized, seen before clone event in parent?", waitPid.tid);
    mUnInitializedThreads.emplace(waitPid.tid, TaskInfo::CreateUnInitializedTask(waitPid));
    return nullptr;
  }

  if (!tc->mConfigurationIsDone && !tc->mIsVForking) {
    DBGLOG(core, "Configuration for newly execed process {} not completed", tc->TaskLeaderTid());
    return nullptr;
  }
  ASSERT(tc != nullptr, "Could not find process that task {} belongs to", waitPid.tid);
  auto task = tc->SetPendingWaitstatus(waitPid);
  return tc->CreateTraceEventFromWaitStatus(*task);
}

void
Tracer::ExecuteCommand(ui::UICommand *cmd) noexcept
{
  auto dapClient = cmd->mDAPClient;
  auto scoped = dapClient->GetResponseArenaAllocator()->ScopeAllocation();
  auto result = cmd->Execute();

  if (result) [[likely]] {
    ASSERT(scoped.GetAllocator() != nullptr, "Arena allocator could not be retrieved");
    auto data = result->Serialize(0);
    if (!data.empty()) {
      dapClient->WriteSerializedProtocolMessage(data);
    }

    delete result;
  }
  delete cmd;
  dapClient->FlushEvents();
}

void
Tracer::HandleTracerEvent(TraceEvent *evt) noexcept
{
#ifdef MDB_DEBUG
  IncrementDebuggerTime();
#endif
  if (!evt->mTask) {
    evt->mTask = GetTaskPointer(evt->mTaskId);
  }

  TraceeController *supervisor = evt->mTask->GetSupervisor();
  // TODO(simon): When we implement RR support (somehow, god knows), we need to be able to tell if we've
  // travelled back in time, or gone forward. This should potentially save us work.
  ASSERT(
    supervisor->mCreationEventTime >= evt->mEventTime, "Event time is before the creation of this supervisor?");
  sLastTraceEventTime = std::max<int>(0, evt->mEventTime);
  if (!supervisor) {
    // out-of-order wait status; defer & wait for complete initilization of new supervisor
    TODO("not impl");
  } else {
    supervisor->HandleTracerEvent(evt);
  }
}

void
Tracer::HandleInternalEvent(InternalEvent evt) noexcept
{
  switch (evt.mType) {
  case InternalEventDiscriminant::InvalidateSupervisor: {
    auto sv = evt.uInvalidateSupervisor.mSupervisor;
    auto it = std::find_if(
      mTracedProcesses.begin(), mTracedProcesses.end(), [sv](const auto &t) { return t.get() == sv; });
    if (it != std::end(mTracedProcesses)) {
      sv->OnTearDown();
      std::unique_ptr<TraceeController> swap = std::move(*it);
      mTracedProcesses.erase(it);
      mExitedProcesses.push_back(std::move(swap));
    }

    if (mTracedProcesses.empty()) {
      sApplicationState = TracerProcess::RequestedShutdown;
    }
  } break;
  case mdb::InternalEventDiscriminant::TerminateDebugging: {
    sApplicationState = TracerProcess::RequestedShutdown;
    break;
  }
  case mdb::InternalEventDiscriminant::InitializedWaitSystem: {
    break;
  }
  default:
    PANIC("Unhandled internal event");
  }
}

void
Tracer::HandleInitEvent(TraceEvent *evt) noexcept
{
  auto tc = GetController(evt->mProcessId);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->mProcessId);
  tc->HandleTracerEvent(evt);
  tc->EmitStopped(evt->mTaskId, ui::dap::StoppedReason::Entry, "attached", true, {});
}

#define ReturnEvalExprError(errorCondition, msg, ...)                                                             \
  if ((errorCondition)) {                                                                                         \
    std::format_to(std::back_inserter(evalResult), msg __VA_OPT__(, ) __VA_ARGS__);                               \
    return ConsoleCommandResult{ false, evalResult };                                                             \
  }

#define OK_RESULT(res)                                                                                            \
  ConsoleCommandResult { true, std::move(res) }

std::pmr::string *
Tracer::EvaluateDebugConsoleExpression(
  const std::string &expression, bool escapeOutput, Allocator *allocator) noexcept
{
  auto res = mConsoleCommandInterpreter->Interpret(expression, allocator);
  return res.mContents;
}

void
Tracer::SetUI(ui::dap::DAP *dap) noexcept
{
  this->mDAP = dap;
}

void
Tracer::KillUI() noexcept
{
  mDAP->clean_up();
}

static int
exec(const Path &program, std::span<const std::pmr::string> programArguments, char **env)
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
  environ = env;
  args[arg_size - 1] = nullptr;
  return execvp(cmd, (char *const *)args.data());
}

Pid
Tracer::Attach(ui::dap::DebugAdapterClient *client, SessionId sessionId, const AttachArgs &args) noexcept
{
  using MatchResult = Pid;

  const auto getUnInitializedSupervisor = [&](SessionId sessionId) -> std::unique_ptr<TraceeController> {
    std::unique_ptr<TraceeController> preparedSupervisor{ nullptr };
    auto it = find_if(mUnInitializedSupervisor, [&](const auto &info) { return info.first == sessionId; });
    VERIFY(it.has_value(), "Failed to find prepared supervisor with id {}", sessionId);

    preparedSupervisor = std::move(it.value()->second);
    return preparedSupervisor;
  };

  return std::visit(
    Match{ [&](const PtraceAttachArgs &ptrace) -> MatchResult {
            auto interface = std::make_unique<tc::PtraceCommander>(ptrace.pid);

            auto preparedSupervisor = getUnInitializedSupervisor(sessionId);
            preparedSupervisor->InitializeSupervisor(
              TargetSession::Attached, std::move(interface), InterfaceType::Ptrace);

            mTracedProcesses.push_back(std::move(preparedSupervisor));

            auto *supervisor = mTracedProcesses.back().get();
            if (const std::optional<Path> execFile = supervisor->GetInterface().ExecedFile(); execFile) {
              const Tid newProcess = supervisor->GetInterface().TaskLeaderTid();
              LoadAndProcessObjectFile(newProcess, *execFile);
            }
            return ptrace.pid;
          },
      [&](const AutoArgs &child) -> MatchResult {
        DBGLOG(core, "Configuring new supervisor for DAP session");
        client->PostDapEvent(new ui::dap::InitializedEvent{ sessionId, child.mExistingProcessId });
        return child.mExistingProcessId;
      },
      [&](const GdbRemoteAttachArgs &gdb) -> MatchResult {
        DBGLOG(core, "Initializing remote protocol interface...");
        // Since we may connect to a remote that is not connected to nuthin,
        // we need an extra step here (via the RemoteSessionConfiguirator), before
        // we can actually be served a TraceeInterface of GdbRemoteCommander type (or actually
        // 0..N of them) Why? Because when we ptrace(someprocess), we know we are attaching to
        // 1 process, that's it. But the remote target might actually be attached to many, and
        // we want our design to be consistent (1 commander / process. Otherwise we turn into
        // gdb hell hole.)
        auto remote_init = tc::RemoteSessionConfigurator{ Tracer::Get().ConnectToRemoteGdb(
          { .host = std::string{ gdb.host }, .port = gdb.port }, {}) };

        std::vector<tc::RemoteProcess> res;

        switch (gdb.type) {
        case RemoteType::RR: {
          auto result = remote_init.configure_rr_session();
          if (result.is_expected()) {
            res = std::move(result.take_value());
          } else {
            PANIC("Failed to configure session");
          }
        } break;
        case RemoteType::GDB: {
          auto result = remote_init.configure_session();
          if (result.is_expected()) {
            res = std::move(result.take_value());
          } else {
            PANIC("Failed to configure session");
          }
        } break;
        }

        auto it = res.begin();
        const auto firstAttachedId = it->tc->TaskLeaderTid();
        bool alreadyAdded = true;

        const auto hookupDapWithRemote =
          [&](auto &&newSupervisor, ui::dap::DebugAdapterClient *client, bool newProc) {
            mTracedProcesses.push_back(std::move(newSupervisor));
            auto *supervisor = mTracedProcesses.back().get();
            auto &ti = supervisor->GetInterface();
            alreadyAdded = false;
            ti.OnExec();
            for (const auto &t : it->threads) {
              supervisor->CreateNewTask(t.tid, false);
            }
            for (auto &entry : supervisor->GetThreads()) {
              entry.mTask->SetUserVisibleStop();
            };

            if (newProc) {
              client->PostDapEvent(new ui::dap::Process{ 0, supervisor->TaskLeaderTid(), "process", false });
            }
          };

        auto mainConnection = mDAP->Get();
        auto unInitializedSupervisor = getUnInitializedSupervisor(sessionId);
        unInitializedSupervisor->InitializeSupervisor(
          TargetSession::Attached, std::move(it->tc), InterfaceType::GdbRemote);
        hookupDapWithRemote(std::move(unInitializedSupervisor), mainConnection, false);
        mainConnection->SetDebugAdapterSessionType(
          (gdb.type == RemoteType::GDB) ? ui::dap::DapClientSession::Attach : ui::dap::DapClientSession::RR);
        ++it;
        for (; it != std::end(res); ++it) {
          hookupDapWithRemote(TraceeController::create(Tracer::Get().NewSupervisorId(),
                                TargetSession::Attached,
                                std::move(it->tc),
                                InterfaceType::GdbRemote),
            mainConnection,
            true);
        }
        return firstAttachedId;
      } },
    args);
}

TraceeController *
Tracer::AddNewSupervisor(std::unique_ptr<TraceeController> tc) noexcept
{
  tc->SetIsOnEntry(true);
  mTracedProcesses.push_back(std::move(tc));
  return mTracedProcesses.back().get();
}

/* static */
pid_t
Tracer::Launch(ui::dap::DebugAdapterClient *debugAdapterClient,
  SessionId sessionId,
  bool stopOnEntry,
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

    if (exec(program, prog_args, environment.data()) == -1) {
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

    Get().AddLaunchedTarget(sessionId, tc::PtraceCfg{ leader }, TargetSession::Launched);
    auto supervisor = Get().mTracedProcesses.back().get();

    debugAdapterClient->SetDebugAdapterSessionType(ui::dap::DapClientSession::Launch);
    supervisor->ConfigureBreakpointBehavior(
      breakpointBehavior.value_or(BreakpointBehavior::StopAllThreadsWhenHit));

    WaitPidResult twr{ .tid = leader, .ws = { .ws = WaitStatusKind::Execed, .exit_code = 0 } };
    auto task = supervisor->RegisterTaskWaited(twr);
    if (task == nullptr) {
      PANIC("Expected a task but could not find one for that wait status");
    }

    supervisor->PostExec(program);

    if (ttyFd) {
      debugAdapterClient->SetTtyOut(*ttyFd, supervisor->mTaskLeader);
    }

    if (stopOnEntry) {
      Set<BreakpointSpecification> fns{ BreakpointSpecification::Create<FunctionBreakpointSpec>(
        {}, {}, "main", false) };
      supervisor->SetFunctionBreakpoints(fns);
    }
    return childPid;
  }
  }
}

std::shared_ptr<SymbolFile>
Tracer::LookupSymbolfile(const std::filesystem::path &path) noexcept
{
  for (const auto &t : mTracedProcesses) {
    if (std::shared_ptr<SymbolFile> sym = t->LookupSymbolFile(path); sym) {
      return sym;
    }
  }
  return nullptr;
}

std::shared_ptr<gdb::RemoteConnection>
Tracer::ConnectToRemoteGdb(
  const tc::GdbRemoteCfg &config, const std::optional<gdb::RemoteSettings> &settings) noexcept
{
  for (auto &t : mTracedProcesses) {
    if (auto conn = t->GetInterface().RemoteConnection(); conn && conn->IsConnectedTo(config.host, config.port)) {
      return conn;
    }
  }
  auto connection = gdb::RemoteConnection::Connect(config.host, config.port, settings);
  if (connection.is_error()) {
    DBGLOG(core, "failed to connect to {}:{}", config.host, config.port);
    PANIC("Exiting after hard failure");
  }
  return connection.take_value();
}

/*static */ u32
Tracer::GenerateNewBreakpointId() noexcept
{
  Get().mBreakpointID++;
  return Get().mBreakpointID;
}

VariableReferenceId
Tracer::NewVariablesReference() noexcept
{
  return ++mVariablesReferenceCounter;
}

VariableReferenceId
Tracer::GetCurrentVariableReferenceBoundary() const noexcept
{
  return mVariablesReferenceCounter;
}

sym::VarContext
Tracer::GetVariableContext(VariableReferenceId varRefKey) noexcept
{
  if (mVariablesReferenceContext.contains(varRefKey)) {
    return mVariablesReferenceContext[varRefKey];
  }
  return nullptr;
}

void
Tracer::DestroyVariablesReference(VariableReferenceId key) noexcept
{
  mVariablesReferenceContext.erase(key);
}

std::unordered_map<Tid, Ref<TaskInfo>> &
Tracer::UnInitializedTasks() noexcept
{
  return mUnInitializedThreads;
}

void
Tracer::RegisterTracedTask(Ref<TaskInfo> newTask) noexcept
{
  ASSERT(!mDebugSessionTasks.contains(newTask->mTid), "task {} has already been registered.", newTask->mTid);
  ASSERT(!mUnInitializedThreads.contains(newTask->mTid), "task {} exists also in an unit state.", newTask->mTid);
  auto tid = newTask->mTid;
  newTask->SetSessionId(mSessionThreadId++);
  mDebugSessionTasks.emplace(tid, std::move(newTask));
}

Ref<TaskInfo>
Tracer::GetTaskReference(Tid tid) noexcept
{
  return RefPtr{ GetTaskPointer(tid) };
}

TaskInfo *
Tracer::GetTaskPointer(Tid tid) noexcept
{
  if (const auto it = mDebugSessionTasks.find(tid); it != std::end(mDebugSessionTasks)) {
    return it->second;
  }
  return nullptr;
}

/* static */
Ref<TaskInfo>
Tracer::GetThreadByTidOrDebugId(Tid tid) noexcept
{
  auto t = Tracer::Get().GetTaskReference(tid);
  if (t) {
    return t;
  }
  return Tracer::Get().GetTaskBySessionId(static_cast<u32>(tid));
}

Ref<TaskInfo>
Tracer::GetTaskBySessionId(u32 sessionId) noexcept
{
  for (auto &task : mDebugSessionTasks) {
    if (task.second->mSessionId == sessionId) {
      return task.second;
    }
  }
  return nullptr;
}

TraceeController *
Tracer::GetSupervisorBySessionId(u32 sessionId) noexcept
{
  for (auto &t : mTracedProcesses) {
    if (t->mSessionId == sessionId) {
      return t.get();
    }
  }
  return nullptr;
}

std::vector<TraceeController *>
Tracer::GetAllProcesses() const noexcept
{
  std::vector<TraceeController *> result;
  result.reserve(mTracedProcesses.size() + mExitedProcesses.size());
  for (auto &p : mTracedProcesses) {
    result.push_back(p.get());
  }

  for (auto &p : mExitedProcesses) {
    result.push_back(p.get());
  }

  return result;
}

ui::dap::DAP *
Tracer::GetDap() const noexcept
{
  return mDAP;
}

void
Tracer::SetVariableContext(std::shared_ptr<VariableContext> ctx) noexcept
{
  auto id = ctx->mId;
  ctx->mTask->AddReference(id);
  mVariablesReferenceContext[id] = std::move(ctx);
}

sym::VarContext
Tracer::CloneFromVariableContext(const VariableContext &ctx) noexcept
{
  if (ctx.mTask->VariableReferenceIsStale(ctx.mId)) {
    // Don't register new context with mVariablesReferenceContext, because the cloned context is cloned from a
    // stale context
    return VariableContext::CloneFrom(ctx.mId - 1, ctx);
  }
  const auto key = NewVariablesReference();

  auto context = VariableContext::CloneFrom(key, ctx);
  mVariablesReferenceContext.emplace(key, context);
  return context;
}

/* static */
void
Tracer::InitializeDapSerializers() noexcept
{
  auto &tracer = Get();
  tracer.mInvalidValueDapSerializer = new sym::InvalidValueVisualizer{};
  tracer.mArrayValueDapSerializer = new sym::ArrayVisualizer{};
  tracer.mPrimitiveValueDapSerializer = new sym::PrimitiveVisualizer{};
  tracer.mDefaultStructDapSerializer = new sym::DefaultStructVisualizer{};
  tracer.mCStringDapSerializer = new sym::CStringVisualizer{};

  tracer.mResolveReference = new sym::ResolveReference{};
  tracer.mResolveCString = new sym::ResolveCString{};
  tracer.mResolveArray = new sym::ResolveArray{};

  DBGLOG(core, "Debug Adapter serializers initialized.");
}

void
Tracer::Shutdown() noexcept
{
  mdb::ThreadPool::ShutdownGlobalPool();
  KillUI();
  mDebugAdapterThread->RequestStop();
#ifdef MDB_PROFILE_LOGGER
  ShutdownProfiling();
#endif
}

void
Tracer::ShutdownProfiling() noexcept
{
  logging::ProfilingLogger::Instance()->Shutdown();
}

u32
Tracer::NewSupervisorId() noexcept
{
  return mSessionProcessId++;
}

/* static */
void
Tracer::InitInterpreterAndStartDebugger(
  std::unique_ptr<DebuggerThread> debugAdapterThread, EventSystem *eventSystem) noexcept
{
  Get().mDebugAdapterThread = std::move(debugAdapterThread);

  auto interpreter = js::Scripting::Create();
  MainLoop(eventSystem, interpreter);
  interpreter->Shutdown();
}

void
Tracer::MainLoop(EventSystem *eventSystem, mdb::js::Scripting *scriptRuntime) noexcept
{
  auto &dbgInstance = Get();
  dbgInstance.sScriptRuntime = scriptRuntime;

  std::vector<ApplicationEvent> readInEvents{};
  readInEvents.reserve(128);

  while (dbgInstance.IsRunning()) {
    if (eventSystem->PollBlocking(readInEvents)) {
      for (auto evt : readInEvents) {
        switch (evt.mEventType) {
        case EventType::WaitStatus: {
          DBGLOG(awaiter, "stop for {}: {}", evt.uWait.mWaitResult.tid, to_str(evt.uWait.mWaitResult.ws.ws));
          if (auto dbg_evt = Tracer::Get().ConvertWaitEvent(evt.uWait.mWaitResult); dbg_evt) {
            dbgInstance.HandleTracerEvent(dbg_evt);
          }
        } break;
        case EventType::Command: {
          dbgInstance.ExecuteCommand(evt.uCommand);
        } break;
        case EventType::TraceeEvent: {
          dbgInstance.HandleTracerEvent(evt.uDebugger);
        } break;
        case EventType::Initialization:
          dbgInstance.HandleInitEvent(evt.uDebugger);
          break;
        case EventType::Internal: {
          dbgInstance.HandleInternalEvent(evt.uInternalEvent);
          break;
        }
        }
      }
      readInEvents.clear();
    }
  }
}
} // namespace mdb