#include "tracer.h"
#include "event_queue.h"
#include "interface/console_command.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "notify_pipe.h"
#include "ptracestop_handlers.h"
#include "supervisor.h"
#include "task.h"
#include "utils/macros.h"
#include "utils/util.h"
#include <algorithm>
#include <charconv>
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

Tracer *Tracer::Instance = nullptr;
bool Tracer::KeepAlive = true;

void
on_sigchild_handler(int)
{
  pid_t pid;
  int stat;
  while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
    EventSystem::Get().PushWaitResult(WaitResult{pid, stat});
  }
}

Tracer::Tracer(utils::Notifier::ReadEnd io_thread_pipe, utils::NotifyManager *events_notifier,
               sys::DebuggerConfiguration init) noexcept
    : mTracedProcesses{}, command_queue_lock(), command_queue(), io_thread_pipe(io_thread_pipe),
      already_launched(false), events_notifier(events_notifier), config(std::move(init))
{
  ASSERT(Tracer::Instance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)Instance);
  Instance = this;
  command_queue = {};
  utils::ThreadPool::get_global_pool()->initialize(config.thread_pool_size());
  mConsoleCommandInterpreter = new ConsoleCommandInterpreter{};
  SetupConsoleCommands();
}

void
Tracer::load_and_process_objfile(pid_t target_pid, const Path &objfile_path) noexcept
{
  // TODO(simon) Once "shared object symbols" (NOT to be confused with Linux' shared objects/so's!) is implemented
  //  we should check if the object file from `objfile_path` has already been loaded into memory
  auto target = get_controller(target_pid);
  if (auto symbol_obj = Tracer::Instance->LookupSymbolfile(objfile_path); symbol_obj == nullptr) {
    auto obj = ObjectFile::CreateObjectFile(target, objfile_path);
    target->RegisterObjectFile(target, std::move(obj), true, nullptr);
  } else {
    target->RegisterSymbolFile(symbol_obj, true);
  }
}

void
Tracer::add_target_set_current(const tc::InterfaceConfig &config, TargetSession session) noexcept
{
  mTracedProcesses.push_back(TraceeController::create(
    session, tc::TraceeCommandInterface::CreateCommandInterface(config), InterfaceType::Ptrace));
  current_target = mTracedProcesses.back().get();
  const auto new_process = current_target->GetInterface().TaskLeaderTid();

  if (!Tracer::use_traceme) {
    PTRACE_OR_PANIC(PTRACE_ATTACH, new_process, 0, 0);
  }
  new_target_set_options(new_process);
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
  auto tc = client->supervisor();
  switch (tc->mInterfaceType) {
  case InterfaceType::Ptrace: {
    switch (config.waitsystem()) {
    case sys::WaitSystem::UseAwaiterThread:
      if (!WaiterSystemConfigured) {
        signal(SIGCHLD, on_sigchild_handler);
      }
      break;
    case sys::WaitSystem::UseSignalHandler:
      if (!WaiterSystemConfigured) {
        signal(SIGCHLD, on_sigchild_handler);
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
  return tc->mStopHandler->prepare_core_from_waitstat(*task);
}

void
Tracer::handle_command(ui::UICommand *cmd) noexcept
{
  auto dapClient = cmd->dap_client;
  DBGLOG(core, "[{}] accepted command {}", dapClient->supervisor() ? dapClient->supervisor()->mTaskLeader : 0,
         cmd->name());

  auto scoped = dapClient->GetResponseArenaAllocator()->ScopeAllocation();
  auto result = cmd->LogExecute();

  ASSERT(scoped.GetAllocator() != nullptr, "Arena allocator could not be retrieved");
  auto data = result->Serialize(0, scoped.GetAllocator());
  if (!data.empty()) {
    dapClient->write(data);
  }

  dapClient->FlushEvents();

  delete cmd;
  delete result;
}

void
Tracer::HandleTracerEvent(TraceEvent *evt) noexcept
{
  auto task = Tracer::Instance->GetTask(evt->tid);
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
  case InternalEventKind::InvalidateSupervisor: {
    auto it = std::find_if(
      mTracedProcesses.begin(), mTracedProcesses.end(),
      [tid = evt.uInvalidateSupervisor.mTaskLeader](const auto &t) { return t->TaskLeaderTid() == tid; });
    if (it != std::end(mTracedProcesses)) {
      if ((*it)->TaskLeaderTid() == evt.uInvalidateSupervisor.mTaskLeader) {
        (*it)->OnTearDown();
        dap->RemoveSource((*it)->GetDebugAdapterProtocolClient());
        mTracedProcesses.erase(it);
      }
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
        if (p != -1 && task->GetSupervisor()->TaskLeaderTid() != p) {
          continue;
        }
        fmt::format_to(
          std::back_inserter(evalResult), "{}.{} user_stop={}, tracer_stop={}, ws={}, signal={}\\r\\n",
          task->GetSupervisor() ? task->GetSupervisor()->TaskLeaderTid() : 0, task->mTid, bool{task->user_stopped},
          bool{task->tracer_stopped}, to_str(task->mLastWaitStatus.ws), task->mLastWaitStatus.signal);
      }

      return OK_RESULT(evalResult);
    });

  mConsoleCommandInterpreter->RegisterConsoleCommand(
    "stopped",
    GenericCommand::CreateCommand(
      "stopped", [&mDebugSessionTasks = mDebugSessionTasks](auto args, auto *allocator) -> ConsoleCommandResult {
        std::pmr::string evalResult{allocator};
        evalResult.reserve(4096);

        for (const auto &[tid, task] : mDebugSessionTasks) {
          if (!task->tracer_stopped) {
            continue;
          }
          fmt::format_to(std::back_inserter(evalResult),
                         "{}.{} user_stop={}, tracer_stop={}, ws={}, signal={}\\r\\n",
                         task->GetSupervisor() ? task->GetSupervisor()->TaskLeaderTid() : 0, task->mTid,
                         bool{task->user_stopped}, bool{task->tracer_stopped}, to_str(task->mLastWaitStatus.ws),
                         task->mLastWaitStatus.signal);
        }

        return OK_RESULT(evalResult);
      }));

  mConsoleCommandInterpreter->RegisterConsoleCommand("threads", threadsCommand);
  mConsoleCommandInterpreter->RegisterConsoleCommand(
    "resume", GenericCommand::CreateCommand("resume", [this](auto args, auto *allocator) -> ConsoleCommandResult {
      std::pmr::string evalResult{allocator};
      evalResult.reserve(4096);
      ReturnEvalExprError(args.size() < 1, "resume command needs a pid.tid argument");
      auto pidtid = utils::split_string(args[0], ".");
      Tid pid, tid = 0;
      ReturnEvalExprError(pidtid.size() < 2, "{} not correct arg for 'resume' command", args[0]);
      auto resp = std::from_chars(pidtid[0].begin(), pidtid[0].end(), pid);
      auto rest = std::from_chars(pidtid[1].begin(), pidtid[1].end(), tid);
      ReturnEvalExprError(resp.ec != std::errc() || rest.ec != std::errc(),
                          "Failed to parse pid tid out of {} and {}", pidtid[0], pidtid[1]);
      auto task = Tracer::Instance->GetTask(tid);
      ReturnEvalExprError(task == nullptr || task->GetSupervisor() == nullptr,
                          "task with id {} not found or doesn't have a supervisor", tid);
      task->GetSupervisor()->ResumeTarget(
        {tc::RunType::Continue, tc::ResumeTarget::Task, task->mLastWaitStatus.signal});
      bool resumed = !bool{task->tracer_stopped};
      fmt::format_to(std::back_inserter(evalResult), "{}.{} resumed={}", task->GetSupervisor()->TaskLeaderTid(),
                     task->mTid, resumed);
      if (resumed) {
        task->GetSupervisor()->GetDebugAdapterProtocolClient()->PostEvent(
          new ui::dap::ContinuedEvent{task->mTid, false});
      }
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

void
Tracer::accept_command(ui::UICommand *cmd) noexcept
{
  {
    LockGuard<SpinLock> lock{command_queue_lock};
    command_queue.push(cmd);
  }
  DBGLOG(core, "accepted command {}", cmd->name());
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
Tracer::attach(const AttachArgs &args) noexcept
{
  using MatchResult = bool;

  return std::visit(
    Match{[&](const PtraceAttachArgs &ptrace) -> MatchResult {
            auto interface = std::make_unique<tc::PtraceCommander>(ptrace.pid);
            mTracedProcesses.push_back(
              TraceeController::create(TargetSession::Attached, std::move(interface), InterfaceType::Ptrace));
            current_target = mTracedProcesses.back().get();
            if (const auto exe_file = current_target->GetInterface().ExecedFile(); exe_file) {
              const auto new_process = current_target->GetInterface().TaskLeaderTid();
              load_and_process_objfile(new_process, *exe_file);
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
              Tracer::Instance->connectToRemoteGdb({.host = gdb.host, .port = gdb.port}, {})};

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
              Tracer::Instance->set_current_to_latest_target();
              auto &ti = current_target->GetInterface();
              client->client_configured(current_target);
              ti.OnExec();
              for (const auto &t : it->threads) {
                current_target->CreateNewTask(t.tid, false);
              }
              for (auto &t : current_target->GetThreads()) {
                t->set_stop();
              }
              client->PostEvent(new ui::dap::StoppedEvent{ui::dap::StoppedReason::Entry,
                                                           "attached",
                                                           client->supervisor()->mTaskLeader,
                                                           {},
                                                           "Attached to session",
                                                           true});
            };

            auto main_connection = dap->main_connection();
            hookupDapWithRemote(std::move(it->tc), main_connection);

            ++it;
            for (; it != std::end(res); ++it) {
              hookupDapWithRemote(std::move(it->tc),
                                  ui::dap::DebugAdapterClient::createSocketConnection(*main_connection));
            }
            return true;
          }},
    args);
}

TraceeController *
Tracer::new_supervisor(std::unique_ptr<TraceeController> tc) noexcept
{
  mTracedProcesses.push_back(std::move(tc));
  current_target = mTracedProcesses.back().get();
  current_target->SetIsOnEntry(true);
  return current_target;
}

static std::vector<int> open_fds;

static int
fdwalk(int (*func)(void *, int), void *arg)
{
  /* Checking __linux__ isn't great but it isn't clear what would be
     better.  There doesn't seem to be a good way to check for this in
     configure.  */
#ifdef __linux__
  DIR *dir;

  dir = opendir("/proc/self/fd");
  if (dir != NULL) {
    struct dirent *entry;
    int result = 0;

    for (entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
      long fd;
      char *tail;

      errno = 0;
      fd = strtol(entry->d_name, &tail, 10);
      if (*tail != '\0' || errno != 0) {
        continue;
      }
      if ((int)fd != fd) {
        /* What can we do here really?  */
        continue;
      }

      if (fd == dirfd(dir)) {
        continue;
      }

      result = func(arg, fd);
      if (result != 0) {
        break;
      }
    }

    closedir(dir);
    return result;
  }
  /* We may fall through to the next case.  */
#endif
#ifdef HAVE_KINFO_GETFILE
  int nfd;
  gdb::unique_xmalloc_ptr<struct kinfo_file[]> fdtbl(kinfo_getfile(getpid(), &nfd));
  if (fdtbl != NULL) {
    for (int i = 0; i < nfd; i++) {
      if (fdtbl[i].kf_fd >= 0) {
        int result = func(arg, fdtbl[i].kf_fd);
        if (result != 0) {
          return result;
        }
      }
    }
    return 0;
  }
  /* We may fall through to the next case.  */
#endif

  {
    int max, fd;

#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
    struct rlimit rlim;

    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0 && rlim.rlim_max != RLIM_INFINITY) {
      max = rlim.rlim_max;
    } else
#endif
    {
#ifdef _SC_OPEN_MAX
      max = sysconf(_SC_OPEN_MAX);
#else
      /* Whoops.  */
      return 0;
#endif /* _SC_OPEN_MAX */
    }

    for (fd = 0; fd < max; ++fd) {
      struct stat sb;
      int result;

      /* Only call FUNC for open fds.  */
      if (fstat(fd, &sb) == -1) {
        continue;
      }

      result = func(arg, fd);
      if (result != 0) {
        return result;
      }
    }

    return 0;
  }
}

static int
do_mark_open_fd(void *ignore, int fd)
{
  open_fds.push_back(fd);
  return 0;
}

void
notice_open_fds(void)
{
  fdwalk(do_mark_open_fd, NULL);
}

void
mark_fd_no_cloexec(int fd)
{
  do_mark_open_fd(NULL, fd);
}

static int
do_close(void *ignore, int fd)
{
  for (int val : open_fds) {
    if (fd == val) {
      /* Keep this one open.  */
      return 0;
    }
  }

  close(fd);
  return 0;
}

void
close_most_fds(void)
{
  fdwalk(do_close, NULL);
}

static sigset_t pass_mask;

/* Update signals to pass to the inferior.  */
static void
pass_signals(std::span<const unsigned char> pass_signals)
{

  sigemptyset(&pass_mask);
  for (int signalNumber = 1; signalNumber < NSIG; signalNumber++) {
    if (signalNumber < pass_signals.size() && pass_signals[signalNumber]) {
      sigaddset(&pass_mask, signalNumber);
    }
  }
}

static struct sigaction original_signal_actions[NSIG];
static sigset_t original_signal_mask;

void
save_original_signals_state(bool quiet)
{
  int res = pthread_sigmask(0, NULL, &original_signal_mask);
  if (res == -1) {
    DBGLOG(warning, "sigprocmask failed: {}", strerror(errno));
  }

  bool found_preinstalled = false;

  for (int i = 1; i < NSIG; i++) {
    struct sigaction *oldact = &original_signal_actions[i];

    res = sigaction(i, NULL, oldact);
    if (res == -1 && errno == EINVAL) {
      /* Some signal numbers in the range are invalid.  */
      continue;
    } else if (res == -1) {
      DBGLOG(warning, "sigaction failed: {}", strerror(errno));
    }
    if (!quiet && oldact->sa_handler != SIG_DFL && oldact->sa_handler != SIG_IGN) {
      found_preinstalled = true;
      DBGLOG(warning, "warning: Found custom handler for signal {} = {}", i, strsignal(i));
    }
  }
}

void
restore_original_signals_state(void)
{
  for (int i = 1; i < NSIG; i++) {
    const int res = sigaction(i, &original_signal_actions[i], NULL);
    if (res == -1 && errno == EINVAL) {
      /* Some signal numbers in the range are invalid.  */
      continue;
    } else if (res == -1) {
      DBGLOG(warning, "sigaction failed: {}", strerror(errno));
    }
  }

  if (pthread_sigmask(SIG_SETMASK, &original_signal_mask, NULL) == -1) {
    DBGLOG(warning, "sigprocmask failed: {}", strerror(errno));
  }
}

void
Tracer::launch(ui::dap::DebugAdapterClient *client, bool stopOnEntry, const Path &program,
               std::span<const std::string> prog_args) noexcept
{
  termios original_tty;
  winsize ws;
  save_original_signals_state(true);

  /* Remember stdio descriptors.  LISTEN_DESC must not be listed, it will be
  opened by remote_prepare.  */
  notice_open_fds();

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

    close_most_fds();

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
    if (Tracer::use_traceme) {
      PTRACE_OR_PANIC(PTRACE_TRACEME, 0, 0, 0);
    } else {
      raise(SIGSTOP);
    }

    restore_original_signals_state();

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
    add_target_set_current(tc::PtraceCfg{leader}, TargetSession::Launched);
    client->client_configured(mTracedProcesses.back().get());
    client->set_session_type(ui::dap::DapClientSession::Launch);
    if (Tracer::use_traceme) {
      TaskWaitResult twr{.tid = leader, .ws = {.ws = WaitStatusKind::Execed, .exit_code = 0}};
      auto task = client->supervisor()->RegisterTaskWaited(twr);
      if (task == nullptr) {
        PANIC("Expected a task but could not find one for that wait status");
      }

      client->supervisor()->PostExec(program);
    } else {
      for (;;) {
        if (const auto ws = waitpid_block(childPid); ws) {
          const auto stat = ws->status;
          if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            TaskWaitResult twr;
            twr.ws.ws = WaitStatusKind::Execed;
            twr.tid = leader;
            DBGLOG(core, "Waited pid after exec! {}, previous: {}", twr.tid, childPid);

            auto task = client->supervisor()->RegisterTaskWaited(twr);
            if (task == nullptr) {
              PANIC("Got no task from registered task wait");
            }
            client->supervisor()->PostExec(program);
            break;
          }
          VERIFY(ptrace(PTRACE_CONT, childPid, 0, 0) != -1, "Failed to continue passed our exec boundary: {}",
                 strerror(errno));
        }
      }
    }

    if (stopOnEntry) {
      Set<FunctionBreakpointSpec> fns{{"main", {}, false}};
      // fns.insert({"main", {}, false});
      client->supervisor()->SetFunctionBreakpoints(fns);
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

NonNullPtr<TraceeController>
Tracer::set_current_to_latest_target() noexcept
{
  ASSERT(!mTracedProcesses.empty(), "Debugger core has no targets");
  current_target = mTracedProcesses.back().get();
  return NonNull(*current_target);
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
Tracer::var_context(u32 varRefKey) noexcept
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