#include "tracer.h"
#include "common.h"
#include "event_queue.h"
#include "interface/attach_args.h"
#include "interface/dap/events.h"
#include "interface/dap/interface.h"
#include "interface/pty.h"
#include "interface/remotegdb/connection.h"
#include "interface/tracee_command/gdb_remote_commander.h"
#include "interface/tracee_command/ptrace_commander.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "notify_pipe.h"
#include "ptracestop_handlers.h"
#include "supervisor.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tasks/lnp.h"
#include "utils/scope_defer.h"
#include "utils/scoped_fd.h"
#include "utils/thread_pool.h"
#include "utils/worker_task.h"
#include <fcntl.h>
#include <fmt/format.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <thread>
#include <type_traits>
#include <unistd.h>

Tracer *Tracer::Instance = nullptr;
bool Tracer::KeepAlive = true;

void
on_sigcld(int)
{
  pid_t pid;
  int stat;
  while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
    const auto wait_result = process_status(pid, stat);
    push_wait_event(0, wait_result);
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
    auto obj = CreateObjectFile(target->task_leader, objfile_path);
    target->register_object_file(obj, true, nullptr);
  } else {
    target->register_symbol_file(symbol_obj, true);
  }
}

void
Tracer::add_target_set_current(const tc::InterfaceConfig &config, TargetSession session) noexcept
{
  targets.push_back(std::make_unique<TraceeController>(
      session, tc::TraceeCommandInterface::createCommandInterface(config), InterfaceType::Ptrace));
  current_target = targets.back().get();
  const auto new_process = current_target->get_interface().task_leader();

  if (!Tracer::use_traceme) {
    PTRACE_OR_PANIC(PTRACE_ATTACH, new_process, 0, 0);
  }
  new_target_set_options(new_process);
}

void
Tracer::thread_exited(LWP lwp, int) noexcept
{
  auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Exited, lwp.tid};
  dap->post_event(evt);
}

TraceeController *
Tracer::get_controller(pid_t pid) noexcept
{
  auto it = std::ranges::find_if(targets, [&pid](auto &t) { return t->task_leader == pid; });
  ASSERT(it != std::end(targets), "Could not find target {} pid", pid);

  return it->get();
}

NonNullPtr<TraceeController>
Tracer::get_current() noexcept
{
  return NonNull(*current_target);
}

void
Tracer::config_done() noexcept
{
  auto tc = get_current();
  switch (tc->interface_type) {
  case InterfaceType::Ptrace: {
    switch (config.waitsystem()) {
    case sys::WaitSystem::UseAwaiterThread:
      get_current()->get_interface().initialize();
      break;
    case sys::WaitSystem::UseSignalHandler:
      signal(SIGCHLD, on_sigcld);
      break;
    }
    break;
  }
  case InterfaceType::GdbRemote:
    get_current()->get_interface().initialize();
    break;
  }
}

CoreEvent *
Tracer::handle_wait_event_2(Tid process_group, TaskWaitResult wait_res) noexcept
{
  if (process_group == 0) {
    for (const auto &tgt : targets) {
      if (std::ranges::any_of(tgt->threads, [&](const auto &t) { return t.tid == wait_res.tid; })) {
        process_group = tgt->task_leader;
      }
    }
  }
  auto tc = get_controller(process_group);
  auto task = tc->set_pending_waitstatus(wait_res);
  return tc->stop_handler->prepare_core_from_waitstat(*task);
}

void
Tracer::handle_command(ui::UICommandPtr cmd) noexcept
{
  DBGLOG(core, "accepted command {}", cmd->name());
  auto result = cmd->execute(this);
  dap->post_event(result);
  delete cmd;
}

void
Tracer::handle_init_event(const CoreEvent *evt) noexcept
{
  ScopedDefer defer{[&]() { delete evt; }};
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);
  process_core_event_determine_proceed(*tc, evt);
  tc->emit_stopped(evt->tid, ui::dap::StoppedReason::Entry, "attached", true, {});
}

void
Tracer::handle_core_event(const CoreEvent *evt) noexcept
{
  ScopedDefer defer{[&]() { delete evt; }};
  auto tc = get_controller(evt->target);
  ASSERT(tc, "Expected to have tracee controller for {}", evt->target);

  tc::ProcessedStopEvent result = process_core_event_determine_proceed(*tc, evt);

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
    auto task = tc->get_task(evt->tid);
    tc->stop_handler->handle_proceed(*task, result);
  }
}

tc::ProcessedStopEvent
Tracer::process_core_event_determine_proceed(TraceeController &tc, const CoreEvent *evt) noexcept
{
  // todo(simon): open up for design that involves user-subscribed event handlers (once we get scripting up and
  // running) It is in this event handling, where we can (at the very end of each handler) emit additional "user
  // facing events", that we also can collect values from (perhaps the user wants to stop for a reason, as such
  // their subscribed event handlers will return `false`).
  using tc::ProcessedStopEvent;
  using MatchResult = ProcessedStopEvent;

  const auto arch = tc.get_interface().arch_info;
  auto task = tc.get_task(evt->tid);
  // we _have_ to do this check here, because the event *might* be a ThreadCreated event
  // and *it* happens *slightly* different depending on if it's a Remote or a Native session that sends it.
  // Unfortunately.
  if (task) {
    if (!evt->registers->empty()) {
      ASSERT(*arch != nullptr, "Passing raw register contents with no architecture description doesn't work.");
      task->set_registers(evt->registers);
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
      t.collect_stop();
    }
  }
  const CoreEvent &r = *evt;
  LogEvent(r, "Handling");
  // clang-format off
  return std::visit(Match {
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
      [&](const ThreadCreated &e) -> MatchResult {
        auto task = tc.get_task(e.thread_id);
        // means this event was produced by a Remote session. Construct the task now
        if(!task) {
          tc.new_task(e.thread_id);
          task = tc.get_task(e.thread_id);
          if (!evt->registers->empty()) {
            ASSERT(*arch != nullptr, "Passing raw register contents with no architecture description doesn't work.");
            task->set_registers(evt->registers);
            for (const auto &p : evt->registers) {
              if (p.first == 16) {
                task->rip_dirty = false;
              }
            }
          }
        }
        task->initialize();
        const auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Started, e.thread_id};
        Tracer::Instance->post_event(evt);

        return ProcessedStopEvent{true, e.resume_action};
        // return ProcessedStopEvent{true, false, tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::Task}};
      },
      [&](const ThreadExited &e) -> MatchResult {
        auto t = tc.get_task(e.thread_id);
        tc.reap_task(*t);
        if(e.process_needs_resuming) {
          return ProcessedStopEvent{!tc.stop_handler->event_settings.thread_exit_stop && e.process_needs_resuming, tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess}};
        } else {
          return ProcessedStopEvent{!tc.stop_handler->event_settings.thread_exit_stop, {}};
        }
      },
      [&](const BreakpointHitEvent &e) -> MatchResult {
        // todo(simon): here we should start building upon global event system, like in gdb, where the user can hook into specific events.
        // in this particular case, we could emit a BreakpointEvent{user_ids_that_were_hit} and let the user look up the bps, and use them instead of passing
        // the data along; that way we get to make it asynchronous - because user code or core code might want to delete the breakpoint _before_ a user wants to use it.
        // Adding this lookup by key feature makes that possible, it also makes the implementation and reasoning about life times *SUBSTANTIALLY* easier.
        auto t = tc.get_task(e.thread_id);

        auto bp_addy = e.address_val->or_else([&]() {
          // Remember: A breakpoint (0xcc) is 1 byte. We need to rewind that 1 byte.
          return std::optional{tc.get_caching_pc(*t).get() - 1};
        }).value();

        auto bp_loc = tc.pbps.location_at(bp_addy);
        const auto users = bp_loc->loc_users();
        bool should_resume = true;
        for (const auto user_id : users) {
          auto user = tc.pbps.get_user(user_id);
          auto on_hit = user->on_hit(tc, *t);
          should_resume = should_resume && !on_hit.stop;
          if (on_hit.retire_bp) {
            tc.pbps.remove_bp(user->id);
          } else {
            t->add_bpstat(user->address().value());
          }
        }
        return ProcessedStopEvent{should_resume, {}};
      },
      [&](const Fork &e) -> MatchResult {
        (void)e;
        TODO("Fork");
        return ProcessedStopEvent{true, {}};
      },
      [&](const Clone &e) -> MatchResult {
        tc.new_task(e.child_tid);
        if(e.vm_info) {
          tc.set_task_vm_info(e.child_tid, e.vm_info.value());
        }
        return ProcessedStopEvent{!tc.stop_handler->event_settings.clone_stop,  {}};
      },
      [&](const Exec &e) -> MatchResult {
        tc.post_exec(e.exec_file);
        return ProcessedStopEvent{!tc.stop_handler->event_settings.exec_stop, {}};
      },
      [&](const ProcessExited &e) -> MatchResult {
        (void)e;
        tc.reap_task(*task);
        return ProcessedStopEvent{false, {}};
      },
      [&](const LibraryEvent &e) -> MatchResult {
        (void)e;
        TODO("LibraryEvent");
        return ProcessedStopEvent{true, {}};
      },
      [&](const Signal &e) -> MatchResult {
        // TODO: Allow signals through / stop process / etc. Allow for configurability here.
        auto t = tc.get_task(e.thread_id);
        tc.stop_all(t);
        if(evt->signal == SIGINT) {
          tc.all_stop.once([t = t->tid, &tc = tc]() {
            tc.emit_stopped(t, ui::dap::StoppedReason::Pause, "Paused", true, {});
          });
        } else {
          tc.all_stop.once([s = t->wait_status.signal, t = t->tid, &tc = tc]() {
            tc.emit_signal_event({.pid = tc.task_leader, .tid = t}, s);
          });
        }
        return ProcessedStopEvent{false, {}};
      },
      [&](const Stepped& e) -> MatchResult {
        if(e.loc_stat) {
          ASSERT(e.loc_stat->stepped_over, "how did we end up here if we did not step over a breakpoint?");
          auto bp_loc = tc.pbps.location_at(e.loc_stat->loc);
          if(e.loc_stat->re_enable_bp) {
            bp_loc->enable(tc.get_interface());
          }
        }

        if(e.stop) {
          tc.emit_stepped_stop({.pid = tc.task_leader, .tid = task->tid});
          return ProcessedStopEvent{false,  {}};
        } else {
          const auto resume = e.loc_stat.transform([](const auto& loc) { return loc.should_resume; }).value_or(false);
          return ProcessedStopEvent{resume, e.resume_when_done};
        }
      },
      [&](const DeferToSupervisor& e) -> MatchResult {
        // And if there is no Proceed action installed, default action is taken (RESUME)
        return ProcessedStopEvent{true && !e.attached, {}};
      },
    },
    *evt->event
  );
  // clang-format on
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
Tracer::post_event(ui::UIResultPtr obj) noexcept
{
  dap->post_event(obj);
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

void
Tracer::execute_pending_commands() noexcept
{
  ui::UICommandPtr pending_command = nullptr;
  while (!command_queue.empty()) {
    // keep the lock as minimum of a time span as possible
    {
      LockGuard<SpinLock> lock{command_queue_lock};
      pending_command = command_queue.front();
      command_queue.pop();
    }
    ASSERT(pending_command != nullptr, "Expected a command but got null");
    DBGLOG(core, "Executing {}", pending_command->name());
    auto result = pending_command->execute(this);
    dap->post_event(result);
    delete pending_command;
    pending_command = nullptr;
  }
}

static int
exec(const Path &program, const std::vector<std::string> &prog_args)
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
  const auto visitor =
      Match{[&](const PtraceAttachArgs &ptrace) -> MatchResult {
              auto interface = std::make_unique<tc::PtraceCommander>(ptrace.pid);
              targets.push_back(std::make_unique<TraceeController>(TargetSession::Attached, std::move(interface),
                                                                   InterfaceType::Ptrace));
              current_target = targets.back().get();
              if (const auto exe_file = current_target->get_interface().execed_file(); exe_file) {
                const auto new_process = current_target->get_interface().task_leader();
                load_and_process_objfile(new_process, *exe_file);
              }
              return true;
            },
            [&](const GdbRemoteAttachArgs &gdb) -> MatchResult {
              DBGLOG(core, "Initializing remote protocol interface...");
              // Since we may connect to a remote that is not connected to nuthin,
              // we need an extra step here (via the RemoteSessionConfiguirator), before
              // we can actually be served a TraceeInterface of GdbRemoteCommander type (or actually 0..N of them)
              // Why? Because when we ptrace(someprocess), we know we are attaching to 1 process, that's it. But
              // the remote target might actually be attached to many, and we want our design to be consistent (1
              // commander / process. Otherwise we turn into gdb hell hole.)
              auto remote_init = tc::RemoteSessionConfigurator{
                  Tracer::Instance->connectToRemoteGdb({.host = gdb.host, .port = gdb.port}, {})};
              auto result = remote_init.configure_session();
              if (result.is_expected()) {
                auto &&ifs = result.take_value();
                for (auto &&interface : ifs) {
                  targets.push_back(std::make_unique<TraceeController>(
                      TargetSession::Attached, std::move(interface.tc), InterfaceType::GdbRemote));
                  Tracer::Instance->set_current_to_latest_target();
                  auto &ti = current_target->get_interface();
                  ti.post_exec();
                  auto newtarget = get_current();
                  for (const auto &t : interface.threads) {
                    newtarget->new_task(t.tid);
                  }
                }
                return true;
              }
              return false;
            }};

  return std::visit(visitor, args);
}

void
Tracer::launch(bool stopAtEntry, Path program, std::vector<std::string> prog_args) noexcept
{
  termios original_tty;
  winsize ws;

  bool could_set_term_settings = (tcgetattr(STDIN_FILENO, &original_tty) != -1);
  if (could_set_term_settings)
    VERIFY(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0, "Failed to get winsize of stdin");

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
    if (Tracer::use_traceme) {
      TaskWaitResult twr{.tid = leader, .ws = {.ws = WaitStatusKind::Execed, .exit_code = 0}};
      auto task = get_current()->register_task_waited(twr);
      if (task == nullptr) {
        PANIC("Expected a task but could not find one for that wait status");
      }
      get_current()->post_exec(program);
      dap->add_tty(res.fd);
    } else {
      for (;;) {
        if (const auto ws = waitpid_block(res.pid); ws) {
          const auto stat = ws->status;
          if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            TaskWaitResult twr;
            twr.ws.ws = WaitStatusKind::Execed;
            twr.tid = leader;
            DBGLOG(core, "Waited pid after exec! {}, previous: {}", twr.tid, res.pid);
            auto task = get_current()->register_task_waited(twr);
            if (task == nullptr) {
              PANIC("Got no task from registered task wait");
            }
            get_current()->post_exec(program);
            dap->add_tty(res.fd);
            break;
          }
          VERIFY(ptrace(PTRACE_CONT, res.pid, 0, 0) != -1, "Failed to continue passed our exec boundary: {}",
                 strerror(errno));
        }
      }
    }

    if (stopAtEntry) {
      Set<FunctionBreakpointSpec> fns{{"main", {}, false}};
      // fns.insert({"main", {}, false});
      get_current()->set_fn_breakpoints(fns);
    }
    break;
  }
  }
}

void
Tracer::detach_target(std::unique_ptr<TraceeController> &&target, bool resume_on_detach) noexcept
{
  // we have taken ownership of `target` in this "sink". Target will be destroyed (should be?)
  target->get_interface().disconnect(!resume_on_detach);
}

void
Tracer::disconnect(bool terminate) noexcept
{
  for (auto &&t : targets) {
    t->get_interface().disconnect(terminate);
  }
  Tracer::KeepAlive = false;
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
    if (auto conn = t->get_interface().remote_connection();
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