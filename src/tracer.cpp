/** LICENSE TEMPLATE */
#include "tracer.h"
#include "awaiter.h"
#include "bp.h"
#include "event_queue.h"
#include "interface/attach_args.h"
#include "interface/console_command.h"
#include "interface/dap/interface.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "js/Context.h"
#include "js/ErrorReport.h"
#include "js/Initialization.h"
#include "js/Warnings.h"
#include "jsfriendapi.h"
#include "mdbjs/event_dispatcher.h"
#include "mdbjs/mdbjs.h"
#include "supervisor.h"
#include "symbolication/value.h"
#include "symbolication/value_visualizer.h"
#include "task.h"
#include "task_scheduling.h"
#include "tracee/util.h"
#include "utils/expected.h"
#include "utils/macros.h"
#include "utils/util.h"
#include <algorithm>
#include <fcntl.h>
#include <fmt/format.h>

#include <interface/dap/dap_defs.h>
#include <interface/dap/events.h>
#include <interface/pty.h>
#include <interface/remotegdb/connection.h>
#include <interface/tracee_command/ptrace_commander.h>

#include <memory_resource>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/objfile.h>
#include <sys/ptrace.h>
#include <utility>

#include <utils/scope_defer.h>
#include <utils/scoped_fd.h>
#include <utils/thread_pool.h>

#include <lib/arena_allocator.h>
#include <lib/lockguard.h>
#include <lib/spinlock.h>

#include <sys/personality.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dirent.h>
namespace mdb {
void
on_sigchild_handler(int)
{
  pid_t pid;
  int stat;
  while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
    EventSystem::Get().PushWaitResult(WaitResult{pid, stat});
  }
}

Tracer::Tracer(sys::DebuggerConfiguration init) noexcept : config(std::move(init))
{
  ASSERT(Tracer::sTracerInstance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)sTracerInstance);
  mConsoleCommandInterpreter = new ConsoleCommandInterpreter{};
}

void
Tracer::LoadAndProcessObjectFile(pid_t target_pid, const Path &objfile_path) noexcept
{
  // TODO(simon) Once "shared object symbols" (NOT to be confused with Linux' shared objects/so's!) is implemented
  //  we should check if the object file from `objfile_path` has already been loaded into memory
  auto target = get_controller(target_pid);
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
  sTracerInstance = new Tracer{std::move(cfg)};
  sTracerInstance->mWaiterThread = WaitStatusReaderThread::Init();
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

void
Tracer::TerminateSession() noexcept
{
  for (auto &t : mTracedProcesses) {
    t->GetInterface().DoDisconnect(true);
    t->GetPublisher(ObserverType::AllStop).Once([sv = t.get()]() {
      EventSystem::Get().PushInternalEvent(InvalidateSupervisor{sv});
    });
  }
  EventSystem::Get().PushInternalEvent(TerminateDebugging{});
}

void
Tracer::AddLaunchedTarget(const tc::InterfaceConfig &config, TargetSession session) noexcept
{
  mTracedProcesses.push_back(TraceeController::create(mSessionProcessId++, session,
                                                      tc::TraceeCommandInterface::CreateCommandInterface(config),
                                                      InterfaceType::Ptrace));

  const auto newProcess = mTracedProcesses.back()->GetInterface().TaskLeaderTid();

  if (!Tracer::sUsePTraceMe) {
    PTRACE_OR_PANIC(PTRACE_ATTACH, newProcess, 0, 0);
  }
  ConfigurePtraceSettings(newProcess);
  mWaiterThread->Start();
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
Tracer::get_controller(pid_t pid) noexcept
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
Tracer::ConvertWaitEvent(TaskWaitResult wait_res) noexcept
{
  auto tc = GetProcessContainingTid(wait_res.tid);
  if (!tc) {
    DBGLOG(core, "Task {} left unitialized, seen before clone event in parent?", wait_res.tid);
    mUnInitializedThreads.emplace(wait_res.tid, TaskInfo::CreateUnInitializedTask(wait_res));
    return nullptr;
  }

  if (!tc->mConfigurationIsDone && !tc->mIsVForking) {
    DBGLOG(core, "Configuration for newly execed process {} not completed", tc->TaskLeaderTid());
    return nullptr;
  }
  ASSERT(tc != nullptr, "Could not find process that task {} belongs to", wait_res.tid);
  auto task = tc->SetPendingWaitstatus(wait_res);
  return tc->CreateTraceEventFromWaitStatus(*task);
}

void
Tracer::ExecuteCommand(ui::UICommand *cmd) noexcept
{
  auto dapClient = cmd->mDAPClient;
  auto scoped = dapClient->GetResponseArenaAllocator()->ScopeAllocation();
  auto result = cmd->LogExecute();

  if (result) [[likely]] {
    ASSERT(scoped.GetAllocator() != nullptr, "Arena allocator could not be retrieved");
    auto data = result->Serialize(0, scoped.GetAllocator());
    if (!data.empty()) {
      dapClient->WriteSerializedProtocolMessage(data);
    }

    delete cmd;
    delete result;
  }
  dapClient->FlushEvents();
}

void
Tracer::InvalidateSessions(int frameTime) noexcept
{
  DBGLOG(core, "implement handling of reverse-execution across thread/process births");
}

void
Tracer::HandleTracerEvent(TraceEvent *evt) noexcept
{
  auto task = Tracer::Get().GetTask(evt->tid);
  TraceeController *supervisor = task->GetSupervisor();
  if ((evt->event_time >= 0) && evt->event_time < sLastTraceEventTime) {
    InvalidateSessions(evt->event_time);
  }
  ASSERT(supervisor->mCreationEventTime >= evt->event_time,
         "Event time is before the creation of this supervisor?");
  sLastTraceEventTime = std::max<int>(0, evt->event_time);
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
    auto it = std::find_if(mTracedProcesses.begin(), mTracedProcesses.end(),
                           [sv](const auto &t) { return t.get() == sv; });
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
  default:
    PANIC("Unhandled internal event");
  }
}

void
Tracer::HandleInitEvent(TraceEvent *evt) noexcept
{
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);
  tc->HandleTracerEvent(evt);
  tc->EmitStopped(evt->tid, ui::dap::StoppedReason::Entry, "attached", true, {});
}

#define ReturnEvalExprError(errorCondition, msg, ...)                                                             \
  if ((errorCondition)) {                                                                                         \
    fmt::format_to(std::back_inserter(evalResult), msg __VA_OPT__(, ) __VA_ARGS__);                               \
    return ConsoleCommandResult{false, evalResult};                                                               \
  }

#define OK_RESULT(res)                                                                                            \
  ConsoleCommandResult { true, std::move(res) }

std::pmr::string *
Tracer::EvaluateDebugConsoleExpression(const std::string &expression, bool escapeOutput,
                                       Allocator *allocator) noexcept
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
exec(const Path &program, std::span<const std::string> prog_args, char **env)
{
  const auto arg_size = prog_args.size() + 2;
  std::vector<const char *> args;
  args.resize(arg_size, nullptr);
  const char *cmd = program.c_str();
  args[0] = cmd;
  auto idx = 1;
  for (const auto &arg : prog_args) {
    args[idx++] = arg.c_str();
  }
  environ = env;
  args[arg_size - 1] = nullptr;
  return execvp(cmd, (char *const *)args.data());
}

Pid
Tracer::Attach(ui::dap::DebugAdapterClient *client, const std::string &sessionId, const AttachArgs &args) noexcept
{
  using MatchResult = Pid;

  return std::visit(
    Match{[&](const PtraceAttachArgs &ptrace) -> MatchResult {
            auto interface = std::make_unique<tc::PtraceCommander>(ptrace.pid);
            mTracedProcesses.push_back(TraceeController::create(Tracer::Get().NewSupervisorId(),
                                                                TargetSession::Attached, std::move(interface),
                                                                InterfaceType::Ptrace));
            auto *supervisor = mTracedProcesses.back().get();
            if (const std::optional<Path> execFile = supervisor->GetInterface().ExecedFile(); execFile) {
              const Tid newProcess = supervisor->GetInterface().TaskLeaderTid();
              LoadAndProcessObjectFile(newProcess, *execFile);
            }
            return ptrace.pid;
          },
          [&](const AutoArgs &child) -> MatchResult {
            DBGLOG(core, "Configuring new supervisor for DAP session");
            client->PostDapEvent(new ui::dap::InitializedEvent{sessionId, child.mExistingProcessId});
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
            auto remote_init = tc::RemoteSessionConfigurator{
              Tracer::Get().ConnectToRemoteGdb({.host = gdb.host, .port = gdb.port}, {})};

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
            mDAP->Get()->PostDapEvent(new ui::dap::InitializedEvent{sessionId, firstAttachedId});
            bool alreadyAdded = true;
            const auto hookupDapWithRemote = [&](auto &&tc, ui::dap::DebugAdapterClient *client, bool newProc) {
              mTracedProcesses.push_back(TraceeController::create(Tracer::Get().NewSupervisorId(),
                                                                  TargetSession::Attached, std::move(tc),
                                                                  InterfaceType::GdbRemote));
              auto *supervisor = mTracedProcesses.back().get();
              auto &ti = supervisor->GetInterface();
              client->AddSupervisor(supervisor);
              alreadyAdded = false;
              ti.OnExec();
              for (const auto &t : it->threads) {
                supervisor->CreateNewTask(t.tid, false);
              }
              for (auto &entry : supervisor->GetThreads()) {
                entry.mTask->SetStop();
              };

              if (newProc) {
                client->PostDapEvent(new ui::dap::Process{0, supervisor->TaskLeaderTid(), "process", false});
              }
            };

            auto main_connection = mDAP->Get();
            hookupDapWithRemote(std::move(it->tc), main_connection, false);
            main_connection->SetDebugAdapterSessionType(
              (gdb.type == RemoteType::GDB) ? ui::dap::DapClientSession::Attach : ui::dap::DapClientSession::RR);
            ++it;
            for (; it != std::end(res); ++it) {
              hookupDapWithRemote(std::move(it->tc), main_connection, true);
            }
            return firstAttachedId;
          }},
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
Tracer::Launch(ui::dap::DebugAdapterClient *debugAdapterClient, const std::string &sessionId, bool stopOnEntry,
               const Path &program, std::span<const std::string> prog_args,
               std::optional<BreakpointBehavior> breakpointBehavior) noexcept
{
  termios original_tty;
  winsize ws;

  bool could_set_term_settings = (tcgetattr(STDIN_FILENO, &original_tty) != -1);
  if (could_set_term_settings) {
    VERIFY(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0, "Failed to get winsize of stdin");
  }

  std::vector<std::string> execvpArgs{};
  execvpArgs.push_back(program.c_str());
  std::copy(prog_args.begin(), prog_args.end(), std::back_inserter(execvpArgs));

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
  const auto fork_result =
    pty_fork(false, could_set_term_settings ? &original_tty : nullptr, could_set_term_settings ? &ws : nullptr);
  // todo(simon): we're forking our already big Tracer process, just to tear it down and exec a new process
  //  I'd much rather like a "stub" process to exec from, that gets handed to us by some "Fork server" thing,
  //  but the logic for that is way more complex and I'm not really interested in solving that problem right now.
  switch (fork_result.index()) {
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
      PANIC(fmt::format("EXECV Failed for {}", program.c_str()));
    }
    _exit(0);
    break;
  }
  default: {
    pid_t childPid = 0;
    std::optional<int> ttyFd = std::nullopt;
    if (fork_result.index() == 1) {
      const auto res = get<PtyParentResult>(fork_result);
      childPid = res.pid;
      ttyFd = res.fd;
    } else {
      const auto res = get<ParentResult>(fork_result);
      childPid = res.child_pid;
    }

    const auto leader = childPid;

    Get().AddLaunchedTarget(tc::PtraceCfg{leader}, TargetSession::Launched);
    auto supervisor = Get().mTracedProcesses.back().get();

    // Inform the debug adater supporting client, that we can now start a configuration init cycle.
    // We also pass along the extension `processId` in the initilization event, so that the debug adapter
    // supporting client can map a debug adapter client to a process id, hence forth.
    debugAdapterClient->PostDapEvent(new ui::dap::InitializedEvent{sessionId, leader});
    debugAdapterClient->AddSupervisor(supervisor);
    debugAdapterClient->SetDebugAdapterSessionType(ui::dap::DapClientSession::Launch);
    supervisor->ConfigureBreakpointBehavior(
      breakpointBehavior.value_or(BreakpointBehavior::StopAllThreadsWhenHit));

    TaskWaitResult twr{.tid = leader, .ws = {.ws = WaitStatusKind::Execed, .exit_code = 0}};
    auto task = supervisor->RegisterTaskWaited(twr);
    if (task == nullptr) {
      PANIC("Expected a task but could not find one for that wait status");
    }

    supervisor->PostExec(program);

    if (ttyFd) {
      debugAdapterClient->SetTtyOut(*ttyFd, supervisor->mTaskLeader);
    }

    if (stopOnEntry) {
      Set<BreakpointSpecification> fns{
        BreakpointSpecification::Create<FunctionBreakpointSpec>({}, {}, "main", false)};
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
Tracer::ConnectToRemoteGdb(const tc::GdbRemoteCfg &config,
                           const std::optional<gdb::RemoteSettings> &settings) noexcept
{
  for (auto &t : mTracedProcesses) {
    if (auto conn = t->GetInterface().RemoteConnection();
        conn && conn->is_connected_to(config.host, config.port)) {
      return conn;
    }
  }
  auto connection = gdb::RemoteConnection::connect(config.host, config.port, settings);
  if (connection.is_error()) {
    DBGLOG(core, "failed to connect to {}:{}", config.host, config.port);
    PANIC("Exiting after hard failure");
  }
  return connection.take_value();
}

u32
Tracer::GenerateNewBreakpointId() noexcept
{
  return ++mBreakpointID;
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
Tracer::GetTask(Tid tid) noexcept
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
  auto t = Tracer::Get().GetTask(tid);
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
mdb::js::AppScriptingInstance &
Tracer::GetScriptingInstance() noexcept
{
  return *sScriptRuntime;
}

/* static */
JSContext *
Tracer::GetJsContext() noexcept
{
  return sApplicationJsContext;
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

u32
Tracer::NewSupervisorId() noexcept
{
  return mSessionProcessId++;
}

/* static */
void
Tracer::InitInterpreterAndStartDebugger(EventSystem *eventSystem) noexcept
{
  if (!JS_Init()) {
    PANIC("Failed to init JS!");
  }

  JSContext *cx = JS_NewContext(JS::DefaultHeapMaxBytes);

  if (!::js::UseInternalJobQueues(cx)) {
    PANIC("Failed to use internal job queues");
  }
  // We must instantiate self-hosting *after* setting up job queue.
  if (!JS::InitSelfHostedCode(cx)) {
    PANIC("init self hosted code failed");
  }
  JS::RootedObject global(cx, mdb::js::RuntimeGlobal::create(cx));

  if (!global) {
    PANIC("Failed to create debugger global object");
  }

  JS::SetWarningReporter(cx, [](JSContext *cx, JSErrorReport *report) { JS::PrintError(stderr, report, true); });
  AppScriptingInstance *js = mdb::js::AppScriptingInstance::Create(cx, global);
  js->InitRuntime();
  JSAutoRealm ar(js->GetRuntimeContext(), js->GetRuntimeGlobal());
  DBGLOG(core, "Javascript initialized. Starting debugger core loop.");
  sApplicationJsContext = cx;
  sScriptRuntime = js;
  // It's now safe to use `ScriptRuntime`
  MainLoop(eventSystem, js);
}

void
Tracer::MainLoop(EventSystem *eventSystem, mdb::js::AppScriptingInstance *scriptRuntime) noexcept
{
  auto &appInstance = Get();
  appInstance.sScriptRuntime = scriptRuntime;

  std::vector<Event> readInEvents{};
  readInEvents.reserve(128);
  while (appInstance.IsRunning()) {
    if (eventSystem->PollBlocking(readInEvents)) {
      for (auto evt : readInEvents) {
#ifdef MDB_DEBUG
        Tracer::Get().DebuggerEventCount()++;
#endif
        switch (evt.type) {
        case EventType::WaitStatus: {
          DBGLOG(awaiter, "stop for {}: {}", evt.uWait.wait.tid, to_str(evt.uWait.wait.ws.ws));
          if (auto dbg_evt = Tracer::Get().ConvertWaitEvent(evt.uWait.wait); dbg_evt) {
            Tracer::Get().HandleTracerEvent(dbg_evt);
          }
        } break;
        case EventType::Command: {
          Tracer::Get().ExecuteCommand(evt.uCommand);
        } break;
        case EventType::TraceeEvent: {
          Tracer::Get().HandleTracerEvent(evt.uDebugger);
        } break;
        case EventType::Initialization:
          Tracer::Get().HandleInitEvent(evt.uDebugger);
          break;
        case EventType::Internal: {
          Tracer::Get().HandleInternalEvent(evt.uInternalEvent);
          break;
        }
        }
      }
      readInEvents.clear();
    }
  }
}
} // namespace mdb