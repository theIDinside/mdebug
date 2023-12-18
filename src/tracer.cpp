#include "tracer.h"
#include "event_queue.h"
#include "interface/dap/events.h"
#include "interface/dap/interface.h"
#include "interface/pty.h"
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
#include "utils/thread_pool.h"
#include "utils/worker_task.h"
#include <fcntl.h>
#include <fmt/format.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

Tracer *Tracer::Instance = nullptr;
bool Tracer::KeepAlive = true;

void
on_sigcld(int sig)
{
  pid_t pid;
  int stat;
  while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
    const auto wait_result = process_status(pid, stat);
    push_event(Event{.process_group = 0, .type = EventType::WaitStatus, .wait = wait_result});
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
  const auto obj_file = mmap_objectfile(objfile_path);
  ASSERT(obj_file != nullptr, "mmap'ing objfile {} failed", objfile_path.c_str());
  auto target = get_controller(target_pid);
  target->register_object_file(obj_file, true, std::nullopt);
  obj_file->initial_dwarf_setup(config.dwarf_config());
}

void
Tracer::add_target_set_current(pid_t task_leader, const Path &path, TargetSession session) noexcept
{
  auto [io_read, io_write] = utils::Notifier::notify_pipe();
  events_notifier->add_notifier(io_read, path.string(), task_leader);
  targets.push_back(std::make_unique<TraceeController>(task_leader, io_write, session, true));
  auto evt = new ui::dap::OutputEvent{
      "console"sv, fmt::format("Task ({}) {} created (task leader: {})", 1, task_leader, task_leader)};
  Tracer::Instance->post_event(evt);
  current_target = targets.back().get();
  load_and_process_objfile(task_leader, path);
  if (!Tracer::use_traceme) {
    PTRACE_OR_PANIC(PTRACE_ATTACH, task_leader, 0, 0);
  }
  new_target_set_options(task_leader);
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

TraceeController *
Tracer::get_current() noexcept
{
  return current_target;
}

void
Tracer::config_done() noexcept
{
  switch (config.waitsystem()) {
  case sys::WaitSystem::UseAwaiterThread:
    get_current()->start_awaiter_thread();
    break;
  case sys::WaitSystem::UseSignalHandler:
    signal(SIGCHLD, on_sigcld);
    break;
  }
}

void
Tracer::handle_wait_event(Tid process_group, TaskWaitResult wait_res) noexcept
{
  if (process_group == 0) {
    process_group = (*targets.begin())->task_leader;
  }
  auto tc = get_controller(process_group);
  tc->set_pending_waitstatus(wait_res);
  auto task = tc->get_task(wait_res.tid);
  tc->ptracestop_handler->handle_wait_event(task);
}

void
Tracer::handle_command(ui::UICommandPtr cmd) noexcept
{
  DLOG("mdb", "accepted command {}", cmd->name());
  auto result = cmd->execute(this);
  dap->post_event(result);
  delete cmd;
}

void
Tracer::wait_for_tracee_events(Tid target_pid) noexcept
{
  auto tc = get_controller(target_pid);
  auto wait_res = tc->wait_pid(nullptr);
  if (!wait_res.has_value())
    return;
  auto wait = *wait_res;
  if (!tc->has_task(wait.tid)) {
    tc->new_task(wait.tid, true);
  }
  auto task = tc->register_task_waited(wait);
  tc->ptracestop_handler->handle_wait_event(task);
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
  DLOG("mdb", "accepted command {}", cmd->name());
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
    DLOG("mdb", "Executing {}", pending_command->name());
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
    add_target_set_current(res.pid, program, TargetSession::Launched);
    if (Tracer::use_traceme) {
      TaskWaitResult twr{.tid = leader, .ws = {.ws = WaitStatusKind::Execed}};
      get_current()->process_exec(get_current()->register_task_waited(twr));
      dap->add_tty(res.fd);
    } else {
      for (;;) {
        if (const auto ws = waitpid_block(res.pid); ws) {
          const auto stat = ws->status;
          if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            TaskWaitResult twr;
            twr.ws.ws = WaitStatusKind::Execed;
            twr.tid = leader;
            DLOG("mdb", "Waited pid after exec! {}, previous: {}", twr.tid, res.pid);
            get_current()->process_exec(get_current()->register_task_waited(twr));
            dap->add_tty(res.fd);
            break;
          }
          VERIFY(ptrace(PTRACE_CONT, res.pid, 0, 0) != -1, "Failed to continue passed our exec boundary: {}",
                 strerror(errno));
        }
      }
    }
    get_current()->reaped_events();
    if (stopAtEntry) {
      get_current()->set_fn_breakpoint("main");
    }
    break;
  }
  }
}

void
Tracer::kill_all_targets() noexcept
{
  for (auto &&t : targets) {
    switch (t->session_type()) {
    case TargetSession::Launched:
      t->terminate_gracefully();
      break;
    case TargetSession::Attached:
      detach(std::move(t));
      break;
    }
  }
  targets.clear();
}

void
Tracer::detach(std::unique_ptr<TraceeController> &&target) noexcept
{
  // we have taken ownership of `target` in this "sink". Target will be destroyed (should be?)
  target->detach();
}

void
Tracer::disconnect() noexcept
{
  kill_all_targets();
  Tracer::KeepAlive = false;
}

const sys::DebuggerConfiguration &
Tracer::get_configuration() const noexcept
{
  return config;
}