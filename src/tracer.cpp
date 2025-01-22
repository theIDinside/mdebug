/** LICENSE TEMPLATE */
#include "tracer.h"
#include "awaiter.h"
#include "event_queue.h"
#include "interface/console_command.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "ptracestop_handlers.h"
#include "supervisor.h"
#include "task.h"
#include "tracee/util.h"
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

void
on_sigchild_handler(int)
{
  pid_t pid;
  int stat;
  while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
    EventSystem::Get().PushWaitResult(WaitResult{pid, stat});
  }
}

Tracer::Tracer(sys::DebuggerConfiguration init) noexcept
    : mTracedProcesses{}, already_launched(false), config(std::move(init)), mWaiterThread(nullptr)
{
  ASSERT(Tracer::sTracerInstance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)sTracerInstance);
  mConsoleCommandInterpreter = new ConsoleCommandInterpreter{};
  SetupConsoleCommands();
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
    t->GetPublisher(ObserverType::AllStop).Once([sv=t.get()](){
      EventSystem::Get().PushInternalEvent(InvalidateSupervisor{sv});
    });
  }
  EventSystem::Get().PushInternalEvent(TerminateDebugging{});
}

void
Tracer::AddLaunchedTarget(const tc::InterfaceConfig &config, TargetSession session) noexcept
{
  mTracedProcesses.push_back(TraceeController::create(
    session, tc::TraceeCommandInterface::CreateCommandInterface(config), InterfaceType::Ptrace));
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

static bool WaiterSystemConfigured = false;
void
Tracer::config_done(ui::dap::DebugAdapterClient *client) noexcept
{
  auto tc = client->GetSupervisor();
  switch (tc->mInterfaceType) {
  case InterfaceType::Ptrace: {
    switch (config.waitsystem()) {
    case sys::WaitSystem::UseAwaiterThread:
      if (!WaiterSystemConfigured) {
        // signal(SIGCHLD, on_sigchild_handler);
      }
      break;
    case sys::WaitSystem::UseSignalHandler:
      if (!WaiterSystemConfigured) {
        // signal(SIGCHLD, on_sigchild_handler);
      }
      break;
    }
    break;
  }
  case InterfaceType::GdbRemote:
    tc->GetInterface().Initialize();
    break;
  }
  tc->mConfigurationIsDone = true;
  WaiterSystemConfigured = true;
}

std::shared_ptr<TaskInfo>
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
Tracer::handle_command(ui::UICommand *cmd) noexcept
{
  auto dapClient = cmd->mDAPClient;
  DBGLOG(core, "[{}] accepted command {}",
         dapClient->GetSupervisor() ? dapClient->GetSupervisor()->mTaskLeader : 0, cmd->name());

  auto scoped = dapClient->GetResponseArenaAllocator()->ScopeAllocation();
  auto result = cmd->LogExecute();

  ASSERT(scoped.GetAllocator() != nullptr, "Arena allocator could not be retrieved");
  auto data = result->Serialize(0, scoped.GetAllocator());
  if (!data.empty()) {
    dapClient->WriteSerializedProtocolMessage(data);
  }

  dapClient->FlushEvents();

  delete cmd;
  delete result;
}

void
Tracer::HandleTracerEvent(TraceEvent *evt) noexcept
{
  auto task = Tracer::Get().GetTask(evt->tid);
  TraceeController *supervisor = task->GetSupervisor();

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
      dap->RemoveSource(sv->GetDebugAdapterProtocolClient());
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

void
Tracer::SetupConsoleCommands() noexcept
{
  auto threadsCommand =
    GenericCommand::CreateCommand("threads", [this](auto args, auto *allocator) -> ConsoleCommandResult {
      std::pmr::string evalResult{allocator};
      Pid p = -1;
      if (!args.empty()) {
        auto param = utils::StrToPid(args[0], false);
        ReturnEvalExprError(!param.has_value(), "Could not parse pid from {}", args[0]);
        p = param.value();
      }

      for (const auto &[tid, task] : mDebugSessionTasks) {
        if ((p != -1 && task->GetSupervisor()->TaskLeaderTid() != p) || task->exited) {
          continue;
        }
        WriteConsoleLine(evalResult, "{}.{} user_stop={}, tracer_stop={}, ws={}, signal={}",
                         task->GetSupervisor() ? task->GetSupervisor()->TaskLeaderTid() : 0, task->mTid,
                         bool{task->user_stopped}, bool{task->tracer_stopped}, to_str(task->mLastWaitStatus.ws),
                         task->mLastWaitStatus.signal);
      }

      return OK_RESULT(evalResult);
    });

  mConsoleCommandInterpreter->RegisterConsoleCommand(
    "stopped",
    GenericCommand::CreateCommand(
      "stopped", [&mDebugSessionTasks = mDebugSessionTasks](auto args, auto *allocator) -> ConsoleCommandResult {
        std::pmr::string evalResult{allocator};
        evalResult.reserve(4096);
        std::optional<int> filter = ParseProcessId(args.empty() ? "" : args[0], false);
        namespace vw = std::ranges::views;

        constexpr auto writeResult = [](auto &evalResult, const auto &task) noexcept {
          WriteConsoleLine(evalResult, "{}.{} user_stop={}, tracer_stop={}, ws={}, signal={}",
                           task->GetSupervisor() ? task->GetSupervisor()->TaskLeaderTid() : 0, task->mTid,
                           bool{task->user_stopped}, bool{task->tracer_stopped}, to_str(task->mLastWaitStatus.ws),
                           task->mLastWaitStatus.signal);
        };

        for (const auto &[tid, task] : mDebugSessionTasks) {
          if (!(task->tracer_stopped || task->user_stopped) || task->exited) {
            continue;
          }
          // we're probably *always* interested in currently-orphan tasks, as these may suggest there's something
          // wrong in debugger core.
          if (filter && (filter != task->GetTaskLeaderTid() && task->GetSupervisor())) {
            continue;
          }
          writeResult(evalResult, task);
        }
        return OK_RESULT(evalResult);
      }));

  mConsoleCommandInterpreter->RegisterConsoleCommand("threads", threadsCommand);
  mConsoleCommandInterpreter->RegisterConsoleCommand(
    "procs",
    GenericCommand::CreateCommand("list ptraced processes", [this](auto, auto *allocator) -> ConsoleCommandResult {
      std::pmr::string evalResult{allocator};
      evalResult.reserve(4096);
      for (const auto &t : Tracer::Get().mTracedProcesses) {
        WriteConsoleLine(evalResult, "{}, parent={}, executable={}", t->TaskLeaderTid(), t->mParentPid,
                         t->mMainExecutable->GetObjectFilePath().filename().c_str());
      }
      return OK_RESULT(evalResult);
    }));
  mConsoleCommandInterpreter->RegisterConsoleCommand(
    "resumeThread",
    GenericCommand::CreateCommand(
      "resumeThread", [this](std::span<std::string_view> args, auto *allocator) -> ConsoleCommandResult {
        std::pmr::string evalResult{allocator};
        evalResult.reserve(4096);
        ReturnEvalExprError(args.size() < 1, "resume command needs a pid.tid argument");
        auto tid = ParseProcessId(args.front(), false);
        ReturnEvalExprError(tid, "input couldn't be parsed into a thread id");
        auto task = Tracer::Get().GetTask(tid.value());
        ReturnEvalExprError(!task || task->exited, "task couldn't be found or has exited");
        ReturnEvalExprError(task->GetSupervisor() != nullptr, "task has no associated supervisor yet");
        task->GetSupervisor()->ResumeTask(
          *task, {.type = tc::RunType::Continue, .target = tc::ResumeTarget::Task, .mDeliverSignal = -1});
        bool resumed = {task->tracer_stopped};
        WriteConsoleLine(evalResult, "{}.{} resumed={}", task->GetSupervisor()->TaskLeaderTid(), task->mTid,
                         resumed);
        if (resumed) {
          task->GetSupervisor()->GetDebugAdapterProtocolClient()->PostEvent(
            new ui::dap::ContinuedEvent{task->mTid, false});
        }
        return OK_RESULT(evalResult);
      }));

  mConsoleCommandInterpreter->RegisterConsoleCommand(
    "resume", GenericCommand::CreateCommand("resume", [this](auto args, auto *allocator) -> ConsoleCommandResult {
      std::pmr::string evalResult{allocator};
      evalResult.reserve(4096);
      ReturnEvalExprError(args.size() < 1, "resume process command needs a pid argument");
      std::optional<pid_t> pid = ParseProcessId(args.front(), false);
      ReturnEvalExprError(!pid.has_value(), "couldn't parse pid argument");
      for (const auto &target : Tracer::Get().mTracedProcesses) {
        if (target->TaskLeaderTid() == pid) {
          bool resumed = target->ResumeTarget({tc::RunType::Continue, tc::ResumeTarget::Task, -1});
          WriteConsoleLine(evalResult, "{} resumed={}", *pid, resumed);
          return OK_RESULT(evalResult);
        }
      }
      WriteConsoleLine(evalResult, "Couldn't find process {}", *pid);
      return OK_RESULT(evalResult);
    }));
}

std::pmr::string
Tracer::EvaluateDebugConsoleExpression(const std::string &expression, bool escapeOutput,
                                       std::pmr::memory_resource *allocator) noexcept
{
  // TODO(simon): write a simple interpreter for custom CLI-like commands. For now, do the absolute dumbest thing
  // of all.
  auto res = mConsoleCommandInterpreter->Interpret(expression, allocator);
  return res.mContents;
}

void
Tracer::set_ui(ui::dap::DAP *dap) noexcept
{
  this->dap = dap;
}

void
Tracer::kill_ui() noexcept
{
  dap->clean_up();
}

static int
exec(const Path &program, std::span<const std::string> prog_args, char **env)
{
  const auto arg_size = prog_args.size() + 2;
  const char *args[arg_size];
  const char *cmd = program.c_str();
  args[0] = cmd;
  auto idx = 1;
  for (const auto &arg : prog_args) {
    args[idx++] = arg.c_str();
  }
  environ = env;
  args[arg_size - 1] = nullptr;
  return execvp(cmd, (char *const *)args);
}

bool
Tracer::Attach(const AttachArgs &args) noexcept
{
  using MatchResult = bool;

  return std::visit(
    Match{[&](const PtraceAttachArgs &ptrace) -> MatchResult {
            auto interface = std::make_unique<tc::PtraceCommander>(ptrace.pid);
            mTracedProcesses.push_back(
              TraceeController::create(TargetSession::Attached, std::move(interface), InterfaceType::Ptrace));
            auto *supervisor = mTracedProcesses.back().get();
            if (const std::optional<Path> execFile = supervisor->GetInterface().ExecedFile(); execFile) {
              const Tid newProcess = supervisor->GetInterface().TaskLeaderTid();
              LoadAndProcessObjectFile(newProcess, *execFile);
            }
            return true;
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
              Tracer::Get().connectToRemoteGdb({.host = gdb.host, .port = gdb.port}, {})};

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
            const auto hookupDapWithRemote = [&](auto &&tc, auto client) {
              mTracedProcesses.push_back(
                TraceeController::create(TargetSession::Attached, std::move(tc), InterfaceType::GdbRemote));
              auto *supervisor = mTracedProcesses.back().get();
              auto &ti = supervisor->GetInterface();
              client->ClientConfigured(supervisor);
              ti.OnExec();
              for (const auto &t : it->threads) {
                supervisor->CreateNewTask(t.tid, false);
              }
              for (auto &entry : supervisor->GetThreads()) {
                entry.mTask->set_stop();
              }
              client->PostEvent(new ui::dap::StoppedEvent{ui::dap::StoppedReason::Entry,
                                                          "attached",
                                                          client->GetSupervisor()->TaskLeaderTid(),
                                                          {},
                                                          "Attached to session",
                                                          true});
            };

            auto main_connection = dap->main_connection();
            hookupDapWithRemote(std::move(it->tc), main_connection);

            ++it;
            for (; it != std::end(res); ++it) {
              hookupDapWithRemote(std::move(it->tc),
                                  ui::dap::DebugAdapterClient::CreateSocketConnection(*main_connection));
            }
            return true;
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

void
Tracer::launch(ui::dap::DebugAdapterClient *client, bool stopOnEntry, const Path &program,
               std::span<const std::string> prog_args,
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
    AddLaunchedTarget(tc::PtraceCfg{leader}, TargetSession::Launched);
    client->ClientConfigured(mTracedProcesses.back().get());
    client->SetDebugAdapterSessionType(ui::dap::DapClientSession::Launch);
    client->GetSupervisor()->ConfigureBreakpointBehavior(
      breakpointBehavior.value_or(BreakpointBehavior::StopAllThreadsWhenHit));

    TaskWaitResult twr{.tid = leader, .ws = {.ws = WaitStatusKind::Execed, .exit_code = 0}};
    auto task = client->GetSupervisor()->RegisterTaskWaited(twr);
    if (task == nullptr) {
      PANIC("Expected a task but could not find one for that wait status");
    }

    client->GetSupervisor()->PostExec(program);

    if (ttyFd) {
      client->SetTtyOut(*ttyFd);
    }

    if (stopOnEntry) {
      Set<FunctionBreakpointSpec> fns{{"main", {}, false}};
      // fns.insert({"main", {}, false});
      client->GetSupervisor()->SetFunctionBreakpoints(fns);
    }
  }
  }
}

void
Tracer::detach_target(std::unique_ptr<TraceeController> &&target, bool resume_on_detach) noexcept
{
  // we have taken ownership of `target` in this "sink". Target will be destroyed (should be?)
  target->GetInterface().Disconnect(!resume_on_detach);
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

const sys::DebuggerConfiguration &
Tracer::getConfig() noexcept
{
  return config;
}

const sys::DebuggerConfiguration &
Tracer::get_configuration() const noexcept
{
  return config;
}

std::shared_ptr<gdb::RemoteConnection>
Tracer::connectToRemoteGdb(const tc::GdbRemoteCfg &config,
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
Tracer::new_breakpoint_id() noexcept
{
  return ++breakpoint_ids;
}

VarRefKey
Tracer::new_key() noexcept
{
  return ++id_counter;
}

VariableContext
Tracer::GetVariableContext(u32 varRefKey) noexcept
{
  return refContext[varRefKey];
}

VarRefKey
Tracer::new_var_context(TraceeController &tc, TaskInfo &t, u32 frameId, SymbolFile *file) noexcept
{
  auto key = new_key();
  refContext[key] =
    VariableContext{.tc = &tc, .t = &t, .symbol_file = file, .frame_id = frameId, .id = static_cast<u16>(key)};
  return key;
}

void
Tracer::destroy_reference(VarRefKey key) noexcept
{
  refContext.erase(key);
}

std::unordered_map<Tid, std::shared_ptr<TaskInfo>> &
Tracer::UnInitializedTasks() noexcept
{
  return mUnInitializedThreads;
}

void
Tracer::RegisterTracedTask(std::shared_ptr<TaskInfo> newTask) noexcept
{
  ASSERT(!mDebugSessionTasks.contains(newTask->mTid), "task {} has already been registered.", newTask->mTid);
  ASSERT(!mUnInitializedThreads.contains(newTask->mTid), "task {} exists also in an unit state.", newTask->mTid);
  auto tid = newTask->mTid;
  mDebugSessionTasks.emplace(tid, std::move(newTask));
}

std::shared_ptr<TaskInfo>
Tracer::GetTask(Tid tid) noexcept
{
  if (const auto it = mDebugSessionTasks.find(tid); it != std::end(mDebugSessionTasks)) {
    return it->second;
  }
  return nullptr;
}

void
Tracer::set_var_context(VariableContext ctx) noexcept
{
  refContext[ctx.id] = ctx;
  ctx.t->add_reference(ctx.id);
}

u32
Tracer::clone_from_var_context(const VariableContext &ctx) noexcept
{
  const auto key = new_key();
  refContext.emplace(key, VariableContext::subcontext(key, ctx));
  return key;
}

bool
VariableContext::valid_context() const noexcept
{
  return tc != nullptr && t != nullptr;
}

std::optional<std::array<ui::dap::Scope, 3>>
VariableContext::scopes_reference(VarRefKey frameKey) const noexcept
{
  auto frame = t->get_callstack().GetFrame(frameKey);
  if (!frame) {
    return {};
  } else {
    return frame->Scopes();
  }
}

sym::Frame *
VariableContext::get_frame(VarRefKey ref) noexcept
{
  switch (type) {
  case ContextType::Frame:
    return t->get_callstack().GetFrame(ref);
  case ContextType::Scope:
  case ContextType::Variable:
    return t->get_callstack().GetFrame(frame_id);
  case ContextType::Global:
    PANIC("Global variables not yet supported");
    break;
  }
  NEVER("Unknown context type");
}

SharedPtr<sym::Value>
VariableContext::get_maybe_value() const noexcept
{
  return t->get_maybe_value(id);
}