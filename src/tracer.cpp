#include "tracer.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "interface/pty.h"
#include "interface/remotegdb/connection.h"
#include "interface/tracee_command/ptrace_commander.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "notify_pipe.h"
#include "ptracestop_handlers.h"
#include "supervisor.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "utils/scope_defer.h"
#include "utils/scoped_fd.h"
#include "utils/thread_pool.h"
#include <fcntl.h>
#include <fmt/format.h>
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
    if (WIFSTOPPED(stat)) {
      const auto res = wait_result_stopped(pid, stat);
      DBGLOG(awaiter, "stop for {}: {}", res.tid, to_str(res.ws.ws));
      push_wait_event(0, res);
    } else if (WIFEXITED(stat)) {
      // We might as well only report this for process-tasks,
      // as DAP doesn't support reporting an exit code for a thread, only for a process,
      // because DAP distinguishes between the two in a way that most OS today, doesn't.
      if (!Tracer::Instance->TraceExitConfigured) {
        // means this is the only place we're getting informed of thread exits
        for (const auto &supervisor : Tracer::Instance->targets) {
          for (const auto &t : supervisor->get_threads()) {
            if (t->tid == pid) {
              DBGLOG(awaiter, "exit for {}", pid);
              push_debugger_event(
                CoreEvent::ThreadExited({supervisor->TaskLeaderTid(), pid, WEXITSTATUS(stat)}, false, {}));
              return;
            }
          }
        }
      } else {
        for (const auto &supervisor : Tracer::Instance->targets) {
          if (supervisor->TaskLeaderTid() == pid) {
            int exit_code = WEXITSTATUS(stat);
            DBGLOG(awaiter, "exit for {}: {}", pid, exit_code);
            push_debugger_event(CoreEvent::ProcessExitEvent(supervisor->TaskLeaderTid(), pid, exit_code, {}));
            return;
          }
        }
      }
    } else if (WIFSIGNALED(stat)) {
      auto signaled_evt =
        TaskWaitResult{.tid = pid, .ws = WaitStatus{.ws = WaitStatusKind::Signalled, .signal = WTERMSIG(stat)}};
      push_wait_event(0, signaled_evt);
    } else {
      PANIC("Unknown wait status event");
    }
  }
}

Tracer::Tracer(utils::Notifier::ReadEnd io_thread_pipe, utils::NotifyManager *events_notifier,
               sys::DebuggerConfiguration init) noexcept
    : targets{}, command_queue_lock(), command_queue(), io_thread_pipe(io_thread_pipe), already_launched(false),
      events_notifier(events_notifier), config(init)
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
  targets.push_back(TraceeController::create(session, tc::TraceeCommandInterface::createCommandInterface(config),
                                             InterfaceType::Ptrace));
  current_target = targets.back().get();
  const auto new_process = current_target->get_interface().TaskLeaderTid();

  if (!Tracer::use_traceme) {
    PTRACE_OR_PANIC(PTRACE_ATTACH, new_process, 0, 0);
  }
  new_target_set_options(new_process);
}

TraceeController *
Tracer::get_controller(pid_t pid) noexcept
{
  auto it = std::ranges::find_if(targets, [&pid](auto &t) { return t->task_leader == pid; });
  ASSERT(it != std::end(targets), "Could not find target {} pid", pid);

  return it->get();
}

static bool WaiterSystemConfigured = false;
void
Tracer::config_done(ui::dap::DebugAdapterClient *client) noexcept
{
  auto tc = client->supervisor();
  switch (tc->interface_type) {
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
    tc->get_interface().Initialize();
    break;
  }
  WaiterSystemConfigured = true;
}

CoreEvent *
Tracer::process_waitevent_to_core(Tid process_group, TaskWaitResult wait_res) noexcept
{
  if (process_group == 0) {
    for (const auto &tgt : targets) {
      if (std::ranges::any_of(tgt->get_threads(), [&](const auto &t) { return t->tid == wait_res.tid; })) {
        process_group = tgt->task_leader;
      }
    }
  }
  auto tc = get_controller(process_group);
  auto task = tc->set_pending_waitstatus(wait_res);
  return tc->stop_handler->prepare_core_from_waitstat(*task);
}

void
Tracer::handle_command(ui::UICommand *cmd) noexcept
{
  DBGLOG(core, "accepted command {}", cmd->name());
  auto result = cmd->execute();

  auto data = result->serialize(0);
  if (!data.empty()) {
    cmd->dap_client->write(data);
  }

  delete cmd;
  delete result;
}

void
Tracer::handle_init_event(const CoreEvent *evt) noexcept
{
  ScopedDefer defer{[&]() { delete evt; }};
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);
  process_core_event(*tc, evt);
  tc->emit_stopped(evt->tid, ui::dap::StoppedReason::Entry, "attached", true, {});
}

void
Tracer::handle_core_event(const CoreEvent *evt) noexcept
{
  ScopedDefer defer{[&]() { delete evt; }};
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);

  tc::ProcessedStopEvent result = process_core_event(*tc, evt);

  // N.B. we _HAVE_ to do this check here (stop_all_requested), not anywhere else, due to the existence of what gdb
  // calls "all stop mode" which means that if *any* thread stops, all other threads are stopped (but they are not
  // reported, it's just implicit to the M.O.) because of that, we will hit a stop, which may request to stop_all
  // and since in all-stop, the other stops are implicit, we won't actually hit this function again, for the other
  // threads, therefore this particular event *has* to have special attention here.

  if (tc->stop_all_requested) {
    if (tc->all_stopped()) {
      tc->notify_all_stopped();
    }
  } else {
    auto task = tc->GetTaskByTid(evt->tid);
    tc->stop_handler->handle_proceed(*task, result);
  }
}
template <typename... T> using M2 = Match<T...>;
tc::ProcessedStopEvent
Tracer::process_core_event(TraceeController &tc, const CoreEvent *evt) noexcept
{
  // todo(simon): open up for design that involves user-subscribed event handlers (once we get scripting up and
  // running) It is in this event handling, where we can (at the very end of each handler) emit additional "user
  // facing events", that we also can collect values from (perhaps the user wants to stop for a reason, as such
  // their subscribed event handlers will return `false`).
  using tc::ProcessedStopEvent;
  using MatchResult = ProcessedStopEvent;

  const auto arch = tc.get_interface().arch_info;
  auto task = tc.GetTaskByTid(evt->tid);
  // we _have_ to do this check here, because the event *might* be a ThreadCreated event
  // and *it* happens *slightly* different depending on if it's a Remote or a Native session that sends it.
  // Unfortunately.
  if (!task) {
    // rr ends up here.
    DBGLOG(core, "task {} created in stop handler because target doesn't support thread events", evt->tid);
    tc.new_task(evt->tid, false);
    task = tc.GetTaskByTid(evt->tid);
    task->initialize();
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
  if (tc.session_all_stop_mode()) {
    for (auto &t : tc.threads) {
      t->set_stop();
      t->stop_collected = true;
    }
  }
  const CoreEvent &r = *evt;
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
      [&](const ThreadCreated &e) -> MatchResult { return tc.handle_thread_created(task, e, evt->registers); },
      [&](const ThreadExited &e) -> MatchResult { return tc.handle_thread_exited(task, e); },
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
                           return std::optional{tc.get_caching_pc(*t).get()};
                         })
                         .value();

        auto bp_loc = tc.user_breakpoints().location_at(bp_addy);
        ASSERT(bp_loc != nullptr, "Expected breakpoint location at 0x{:x}", bp_addy);
        const auto users = bp_loc->loc_users();
        bool should_resume = true;
        for (const auto user_id : users) {
          auto user = tc.user_breakpoints().get_user(user_id);
          auto on_hit = user->on_hit(tc, *t);
          should_resume = should_resume && !on_hit.stop;
          if (on_hit.retire_bp) {
            tc.user_breakpoints().remove_bp(user->id);
          } else {
            t->add_bpstat(user->address().value());
          }
        }
        return ProcessedStopEvent{should_resume, {}};
      },
      [&](const Fork &e) -> MatchResult { return tc.handle_fork(e); },
      [&](const Clone &e) -> MatchResult {
        tc.new_task(e.child_tid, true);
        if (e.vm_info) {
          tc.set_task_vm_info(e.child_tid, e.vm_info.value());
        }
        return ProcessedStopEvent{!tc.stop_handler->event_settings.clone_stop, {}};
      },
      [&](const Exec &e) -> MatchResult {
        tc.post_exec(e.exec_file);
        Set<FunctionBreakpointSpec> fns{{"main", {}, false}};
        tc.set_fn_breakpoints(fns);
        tc.dap_client->post_event(new ui::dap::Process{e.exec_file, true});
        return ProcessedStopEvent{!tc.stop_handler->event_settings.exec_stop, {}};
      },
      [&](const ProcessExited &e) -> MatchResult { return tc.handle_process_exit(e); },
      [&](const LibraryEvent &e) -> MatchResult {
        (void)e;
        TODO("LibraryEvent");
        return ProcessedStopEvent{true, {}};
      },
      [&](const Signal &e) -> MatchResult {
        // TODO: Allow signals through / stop process / etc. Allow for configurability here.
        auto t = tc.GetTaskByTid(e.thread_id);
        tc.stop_all(t);
        if (evt->signal == SIGINT) {
          tc.observer(ObserverType::AllStop).once([t = t->tid, &tc = tc]() {
            tc.emit_stopped(t, ui::dap::StoppedReason::Pause, "Paused", true, {});
          });
        } else {
          tc.observer(ObserverType::AllStop).once([s = t->wait_status.signal, t = t->tid, &tc = tc]() {
            tc.emit_signal_event({.pid = tc.task_leader, .tid = t}, s);
          });
        }
        return ProcessedStopEvent{false, {}};
      },
      [&](const Stepped &e) -> MatchResult {
        if (e.loc_stat) {
          ASSERT(e.loc_stat->stepped_over, "how did we end up here if we did not step over a breakpoint?");
          auto bp_loc = tc.user_breakpoints().location_at(e.loc_stat->loc);
          if (e.loc_stat->re_enable_bp) {
            bp_loc->enable(tc.get_interface());
          }
        }

        if (e.stop) {
          task->user_stopped = true;
          tc.emit_stepped_stop({.pid = tc.task_leader, .tid = task->tid});
          return ProcessedStopEvent{false, {}};
        } else {
          const auto resume =
            e.loc_stat.transform([](const auto &loc) { return loc.should_resume; }).value_or(false);
          return ProcessedStopEvent{resume, e.resume_when_done};
        }
      },
      [&](const EntryEvent &e) noexcept -> MatchResult {
        tc.set_on_entry(false);
        // apply session breakpoints to new process space
        if (e.should_stop) {
          // emit stop event
          tc.emit_stopped(e.thread_id, ui::dap::StoppedReason::Entry, "forked", true, {});
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
            targets.push_back(
              TraceeController::create(TargetSession::Attached, std::move(interface), InterfaceType::Ptrace));
            current_target = targets.back().get();
            if (const auto exe_file = current_target->get_interface().ExecedFile(); exe_file) {
              const auto new_process = current_target->get_interface().TaskLeaderTid();
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
              targets.push_back(
                TraceeController::create(TargetSession::Attached, std::move(tc), InterfaceType::GdbRemote));
              Tracer::Instance->set_current_to_latest_target();
              auto &ti = current_target->get_interface();
              client->client_configured(current_target);
              ti.OnExec();
              for (const auto &t : it->threads) {
                current_target->new_task(t.tid, false);
              }
              for (auto &t : current_target->get_threads()) {
                t->set_stop();
              }
              client->post_event(new ui::dap::StoppedEvent{ui::dap::StoppedReason::Entry,
                                                           "attached",
                                                           client->supervisor()->task_leader,
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
  targets.push_back(std::move(tc));
  current_target = targets.back().get();
  current_target->set_on_entry(true);
  return current_target;
}

void
Tracer::launch(ui::dap::DebugAdapterClient *client, bool stopOnEntry, Path program,
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
    client->client_configured(targets.back().get());
    client->set_session_type(ui::dap::DapClientSession::Launch);
    if (Tracer::use_traceme) {
      TaskWaitResult twr{.tid = leader, .ws = {.ws = WaitStatusKind::Execed, .exit_code = 0}};
      auto task = client->supervisor()->register_task_waited(twr);
      if (task == nullptr) {
        PANIC("Expected a task but could not find one for that wait status");
      }

      client->supervisor()->post_exec(program);
    } else {
      for (;;) {
        if (const auto ws = waitpid_block(res.pid); ws) {
          const auto stat = ws->status;
          if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            TaskWaitResult twr;
            twr.ws.ws = WaitStatusKind::Execed;
            twr.tid = leader;
            DBGLOG(core, "Waited pid after exec! {}, previous: {}", twr.tid, res.pid);

            auto task = client->supervisor()->register_task_waited(twr);
            if (task == nullptr) {
              PANIC("Got no task from registered task wait");
            }
            client->supervisor()->post_exec(program);
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
      client->supervisor()->set_fn_breakpoints(fns);
    }
  }
  }
}

void
Tracer::detach_target(std::unique_ptr<TraceeController> &&target, bool resume_on_detach) noexcept
{
  // we have taken ownership of `target` in this "sink". Target will be destroyed (should be?)
  target->get_interface().Disconnect(!resume_on_detach);
}

std::shared_ptr<SymbolFile>
Tracer::LookupSymbolfile(const std::filesystem::path &path) noexcept
{
  for (const auto &t : targets) {
    if (std::shared_ptr<SymbolFile> sym = t->lookup_symbol_file(path); sym) {
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
  for (auto &t : targets) {
    if (auto conn = t->get_interface().RemoteConnection();
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
  ASSERT(!targets.empty(), "Debugger core has no targets");
  current_target = targets.back().get();
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
  return std::find_if(Tracer::Instance->targets.begin(), Tracer::Instance->targets.end(),
                      [client](auto &ptr) { return ptr->get_dap_client() == client; });
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