#include "tracer.h"
#include "event_queue.h"
#include "notify_pipe.h"
#include "ptracestop_handlers.h"
#include "supervisor.h"
#include "task.h"
#include <fcntl.h>
#include <fmt/format.h>

#include <interface/dap/dap_defs.h>
#include <interface/dap/events.h>
#include <interface/pty.h>
#include <interface/remotegdb/connection.h>
#include <interface/tracee_command/ptrace_commander.h>

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
        // tc->get_interface().initialize();
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

  if (!tc || !tc->mConfigurationIsDone) {
    DBGLOG(core, "Task {} left unitialized, seen before clone event in parent?", wait_res.tid);
    mUnInitializedThreads.emplace(wait_res.tid, TaskInfo::CreateUnInitializedTask(wait_res));
    return nullptr;
  }
  ASSERT(tc != nullptr, "Could not find process that task {} belongs to", wait_res.tid);
  auto task = tc->SetPendingWaitstatus(wait_res);
  return tc->mStopHandler->prepare_core_from_waitstat(*task);
}

void
Tracer::handle_command(ui::UICommand *cmd) noexcept
{
  DBGLOG(core, "accepted command {}", cmd->name());
  auto result = cmd->LogExecute();

  auto scoped = cmd->dap_client->GetResponseArenaAllocator()->ScopeAllocation();
  ASSERT(scoped.GetAllocator() != nullptr, "Arena allocator could not be retrieved");
  auto data = result->Serialize(0, scoped.GetAllocator());
  if (!data.empty()) {
    cmd->dap_client->write(data);
  }

  delete cmd;
  delete result;
}

void
Tracer::handle_init_event(const TraceEvent *evt) noexcept
{
  ScopedDefer defer{[&]() { delete evt; }};
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);
  process_core_event(*tc, evt);
  tc->EmitStopped(evt->tid, ui::dap::StoppedReason::Entry, "attached", true, {});
}

void
Tracer::handle_core_event(const TraceEvent *evt) noexcept
{
  ScopedDefer defer{[&]() { delete evt; }};
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);

  tc::ProcessedStopEvent result = process_core_event(*tc, evt);

  if (result.mThreadExited) {
    for (auto &t : tc->GetExitedThreads()) {
      if (evt->tid == t->tid) {
        tc->mStopHandler->handle_proceed(*t, result);
        return;
      }
    }
  }

  // N.B. we _HAVE_ to do this check here (stop_all_requested), not anywhere else, due to the existence of what gdb
  // calls "all stop mode" which means that if *any* thread stops, all other threads are stopped (but they are not
  // reported, it's just implicit to the M.O.) because of that, we will hit a stop, which may request to stop_all
  // and since in all-stop, the other stops are implicit, we won't actually hit this function again, for the other
  // threads, therefore this particular event *has* to have special attention here.
  if (result.mProcessExited) {
    CleanUp(tc);
  } else if (tc->mStopAllTasksRequested) {
    if (tc->IsAllStopped()) {
      tc->EmitAllStopped();
    }
  } else {
    auto task = tc->GetTaskByTid(evt->tid);
    tc->mStopHandler->handle_proceed(*task, result);
  }
}
template <typename... T> using M2 = Match<T...>;
tc::ProcessedStopEvent
Tracer::process_core_event(TraceeController &tc, const TraceEvent *evt) noexcept
{
  // todo(simon): open up for design that involves user-subscribed event handlers (once we get scripting up and
  // running) It is in this event handling, where we can (at the very end of each handler) emit additional "user
  // facing events", that we also can collect values from (perhaps the user wants to stop for a reason, as such
  // their subscribed event handlers will return `false`).
  using tc::ProcessedStopEvent;
  using MatchResult = ProcessedStopEvent;

  const auto arch = tc.GetInterface().arch_info;
  auto task = tc.GetTaskByTid(evt->tid);
  // we _have_ to do this check here, because the event *might* be a ThreadCreated event
  // and *it* happens *slightly* different depending on if it's a Remote or a Native session that sends it.
  // Unfortunately.
  if (!task) {
    // rr ends up here.
    DBGLOG(core, "task {} created in stop handler because target doesn't support thread events", evt->tid);
    tc.CreateNewTask(evt->tid, false);
    task = tc.GetTaskByTid(evt->tid);
  }
  if (task) {
    if (!evt->registers->empty()) {
      ASSERT(*arch != nullptr, "Passing raw register contents with no architecture description doesn't work.");
      task->StoreToRegisterCache(evt->registers);
      for (const auto &p : evt->registers) {
        if (p.first == 16) {
          task->rip_dirty = false;
        }
      }
    }
    task->collect_stop();
  }
  if (tc.IsSessionAllStopMode()) {
    for (auto &t : tc.mThreads) {
      t->set_stop();
      t->stop_collected = true;
    }
  }
  const TraceEvent &r = *evt;
  LogEvent(r, "Handling");

  return std::visit(
    Match{
      [&](const WatchpointEvent &e) -> MatchResult {
        (void)e;
        TODO("WatchpointEvent");
        return ProcessedStopEvent::ResumeAny();
      },
      [&](const SyscallEvent &e) -> MatchResult {
        (void)e;
        TODO("SyscallEvent");
        return ProcessedStopEvent::ResumeAny();
      },
      [&](const ThreadCreated &e) -> MatchResult { return tc.HandleThreadCreated(task, e, evt->registers); },
      [&](const ThreadExited &e) -> MatchResult { return tc.HandleThreadExited(task, e); },
      [&](const BreakpointHitEvent &e) -> MatchResult {
        // todo(simon): here we should start building upon global event system, like in gdb, where the user can
        // hook into specific events. in this particular case, we could emit a
        // BreakpointEvent{user_ids_that_were_hit} and let the user look up the bps, and use them instead of
        // passing the data along; that way we get to make it asynchronous - because user code or core code
        // might want to delete the breakpoint _before_ a user wants to use it. Adding this lookup by key
        // feature makes that possible, it also makes the implementation and reasoning about life times
        // *SUBSTANTIALLY* easier.
        auto t = tc.GetTaskByTid(e.thread_id);

        auto bp_addy = e.address_val
                         ->or_else([&]() {
                           // Remember: A breakpoint (0xcc) is 1 byte. We need to rewind that 1 byte.
                           return std::optional{tc.CacheAndGetPcFor(*t).get()};
                         })
                         .value();

        auto bp_loc = tc.GetUserBreakpoints().location_at(bp_addy);
        ASSERT(bp_loc != nullptr, "Expected breakpoint location at 0x{:x}", bp_addy);
        const auto users = bp_loc->loc_users();
        ASSERT(!bp_loc->loc_users().empty(),
               "[task={}]: A breakpoint location with no user is a rogue/leaked breakpoint at 0x{:x}", t->tid,
               bp_addy);
        bool should_resume = true;
        for (const auto user_id : users) {
          auto user = tc.GetUserBreakpoints().get_user(user_id);
          auto on_hit = user->on_hit(tc, *t);
          should_resume = should_resume && !on_hit.stop;
          if (on_hit.retire_bp) {
            tc.GetUserBreakpoints().remove_bp(user->id);
          } else {
            t->add_bpstat(user->address().value());
          }
        }
        return ProcessedStopEvent{should_resume, {}};
      },
      [&](const ForkEvent &e) -> MatchResult { return tc.HandleFork(e); },
      [&](const Clone &e) -> MatchResult { return tc.HandleClone(e); },
      [&](const Exec &e) -> MatchResult {
        tc.PostExec(e.exec_file);
        tc.mDebugAdapterClient->post_event(new ui::dap::Process{e.exec_file, true});
        return ProcessedStopEvent{!tc.mStopHandler->event_settings.exec_stop, {}};
      },
      [&](const ProcessExited &e) -> MatchResult { return tc.HandleProcessExit(e); },
      [&](const LibraryEvent &e) -> MatchResult {
        (void)e;
        TODO("LibraryEvent");
        return ProcessedStopEvent{true, {}};
      },
      [&](const Signal &e) -> MatchResult {
        // TODO: Allow signals through / stop process / etc. Allow for configurability here.
        auto t = tc.GetTaskByTid(e.thread_id);
        tc.StopAllTasks(t);
        if (evt->signal == SIGINT) {
          tc.GetPublisher(ObserverType::AllStop).once([t = t->tid, &tc = tc]() {
            tc.EmitStopped(t, ui::dap::StoppedReason::Pause, "Paused", true, {});
          });
        } else {
          tc.GetPublisher(ObserverType::AllStop).once([s = t->wait_status.signal, t = t->tid, &tc = tc]() {
            tc.EmitSignalEvent({.pid = tc.mTaskLeader, .tid = t}, s);
          });
        }
        return ProcessedStopEvent{false, {}};
      },
      [&](const Stepped &e) -> MatchResult {
        if (e.loc_stat) {
          ASSERT(e.loc_stat->stepped_over, "how did we end up here if we did not step over a breakpoint?");
          auto bp_loc = tc.GetUserBreakpoints().location_at(e.loc_stat->loc);
          if (e.loc_stat->re_enable_bp) {
            bp_loc->enable(tc.GetInterface());
          }
        }

        if (e.stop) {
          task->user_stopped = true;
          tc.EmitSteppedStop({.pid = tc.mTaskLeader, .tid = task->tid});
          return ProcessedStopEvent{false, {}};
        } else {
          const auto resume =
            e.loc_stat.transform([](const auto &loc) { return loc.should_resume; }).value_or(false);
          return ProcessedStopEvent{resume, e.resume_when_done};
        }
      },
      [&](const EntryEvent &e) noexcept -> MatchResult {
        tc.SetIsOnEntry(false);
        // apply session breakpoints to new process space
        if (e.should_stop) {
          // emit stop event
          tc.EmitStopped(e.thread_id, ui::dap::StoppedReason::Entry, "forked", true, {});
        } else {
          // say "thread created / started"
        }
        return ProcessedStopEvent{!e.should_stop, {}};
      },
      [&](const DeferToSupervisor &e) -> MatchResult {
        // And if there is no Proceed action installed, default action is taken (RESUME)
        return ProcessedStopEvent{true && !e.attached, {}};
      },
    },
    *evt->event);
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
exec(const Path &program, std::span<const std::string> prog_args)
{
  const auto arg_size = prog_args.size() + 2;
  const char *args[arg_size];
  const char *cmd = program.c_str();
  args[0] = cmd;
  auto idx = 1;
  for (const auto &arg : prog_args) {
    args[idx] = arg.c_str();
  }
  args[arg_size - 1] = nullptr;
  return execv(cmd, (char *const *)args);
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
              client->post_event(new ui::dap::StoppedEvent{ui::dap::StoppedReason::Entry,
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
                                  ui::dap::DebugAdapterClient::createSocketConnection(main_connection));
            }
            return true;
          }},
    args);
}

TraceeController *
Tracer::new_supervisor(std::unique_ptr<TraceeController> &&tc) noexcept
{
  mTracedProcesses.push_back(std::move(tc));
  current_target = mTracedProcesses.back().get();
  current_target->SetIsOnEntry(true);
  return current_target;
}

void
Tracer::launch(ui::dap::DebugAdapterClient *client, bool stopOnEntry, const Path &program,
               std::span<const std::string> prog_args) noexcept
{
  termios original_tty;
  winsize ws;

  bool could_set_term_settings = (tcgetattr(STDIN_FILENO, &original_tty) != -1);
  if (could_set_term_settings) {
    VERIFY(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0, "Failed to get winsize of stdin");
  }

  const auto fork_result =
    pty_fork(could_set_term_settings ? &original_tty : nullptr, could_set_term_settings ? &ws : nullptr);
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
    if (Tracer::use_traceme) {
      PTRACE_OR_PANIC(PTRACE_TRACEME, 0, 0, 0);
    } else {
      raise(SIGSTOP);
    }

    if (exec(program, prog_args) == -1) {
      PANIC(fmt::format("EXECV Failed for {}", program.c_str()));
    }
    _exit(0);
    break;
  }
  default: {
    const auto res = get<PtyParentResult>(fork_result);
    const auto leader = res.pid;
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
        if (const auto ws = waitpid_block(res.pid); ws) {
          const auto stat = ws->status;
          if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            TaskWaitResult twr;
            twr.ws.ws = WaitStatusKind::Execed;
            twr.tid = leader;
            DBGLOG(core, "Waited pid after exec! {}, previous: {}", twr.tid, res.pid);

            auto task = client->supervisor()->RegisterTaskWaited(twr);
            if (task == nullptr) {
              PANIC("Got no task from registered task wait");
            }
            client->supervisor()->PostExec(program);
            break;
          }
          VERIFY(ptrace(PTRACE_CONT, res.pid, 0, 0) != -1, "Failed to continue passed our exec boundary: {}",
                 strerror(errno));
        }
      }
    }
    client->set_tty_out(res.fd);
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

void
Tracer::CleanUp(TraceeController *tc) noexcept
{
  auto it = std::ranges::find_if(mTracedProcesses, [tc](const auto &t) { return t.get() == tc; });
  if (it != std::end(mTracedProcesses)) {
    tc->TearDown(false);
  }
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

std::vector<std::unique_ptr<TraceeController>>::iterator
Tracer::find_controller_by_dap(ui::dap::DebugAdapterClient *client) noexcept
{
  return std::find_if(Tracer::Instance->mTracedProcesses.begin(), Tracer::Instance->mTracedProcesses.end(),
                      [client](auto &ptr) { return ptr->GetDebugAdapterProtocolClient() == client; });
}

std::unordered_map<Tid, std::shared_ptr<TaskInfo>> &
Tracer::UnInitializedTasks() noexcept
{
  return mUnInitializedThreads;
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