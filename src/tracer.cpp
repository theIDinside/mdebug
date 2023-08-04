#include "tracer.h"
#include "./interface/dap/interface.h"
#include "common.h"
#include "fmt/format.h"
#include "interface/dap/events.h"
#include "interface/pty.h"
#include "interface/ui_command.h"
#include "interface/ui_result.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include "notify_pipe.h"
#include "posix/argslist.h"
#include "ptrace.h"
#include "ptracestop_handlers.h"
#include "symbolication/cu.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tracee_controller.h"
#include "utils/logger.h"
#include <algorithm>
#include <bits/chrono.h>
#include <bits/ranges_util.h>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <ranges>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

Tracer *Tracer::Instance = nullptr;

std::string_view
add_object_err(AddObjectResult r)
{
  switch (r) {
  case AddObjectResult::OK:
    return "OK";
  case AddObjectResult::MMAP_FAILED:
    return "Mmap Failed";
  case AddObjectResult::FILE_NOT_EXIST:
    return "File didn't exist";
  }
}

Tracer::Tracer(utils::Notifier::ReadEnd io_thread_pipe, utils::NotifyManager *events_notifier) noexcept
    : targets{}, object_files(), command_queue_lock(), command_queue(), io_thread_pipe(io_thread_pipe),
      already_launched(false), events_notifier(events_notifier),
      prev_time(std::chrono::high_resolution_clock::now())
{
  ASSERT(Tracer::Instance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)Instance);
  Instance = this;
  this->command_queue = {};
}

void
Tracer::load_and_process_objfile(pid_t target_pid, const Path &objfile_path) noexcept
{
  const auto res = mmap_objectfile(objfile_path);
  if (res != AddObjectResult::OK) {
    logging::get_logging()->log(
        "mdb", fmt::format("Failed to load object file {}; Error {}", objfile_path.c_str(), add_object_err(res)));
  }
  const auto obj_file = object_files.back();
  Elf::parse_objfile(obj_file);
  auto target = get_controller(target_pid);
  target->register_object_file(obj_file);
  CompilationUnitBuilder cu_builder{obj_file};
  std::vector<std::unique_ptr<CUProcessor>> cu_processors{};
  auto total = cu_builder.build_cu_headers();
  std::vector<std::thread> jobs{};

  for (auto &cu_hdr : total) {
    jobs.push_back(std::thread{[obj_file, cu_hdr, tgt = target]() {
      auto proc = prepare_cu_processing(obj_file, cu_hdr, tgt);
      auto compile_unit_die = proc->read_dies();
      if (compile_unit_die->tag == DwarfTag::DW_TAG_compile_unit) {
        proc->process_compile_unit_die(compile_unit_die.release());
      } else {
        PANIC("Unexpected non-compile unit DIE parsed");
      }
    }});
  }

  for (auto &&j : jobs) {
    j.join();
  }
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
  PTRACE_OR_PANIC(PTRACE_SEIZE, task_leader, 0, 0);
  new_target_set_options(task_leader);
}

AddObjectResult
Tracer::mmap_objectfile(const Path &path) noexcept
{
  if (!fs::exists(path))
    return AddObjectResult::FILE_NOT_EXIST;

  ASSERT(std::ranges::find_if(object_files, [&](ObjectFile *obj) { return obj->path == path; }) ==
             std::end(object_files),
         "Object file from {} has already been loaded", path.c_str());

  auto fd = ScopedFd::open_read_only(path);
  const auto addr = mmap_file<u8>(fd, fd.file_size(), true);

  auto obj = new ObjectFile{path, fd.file_size(), addr};
  object_files.push_back(obj);

  return AddObjectResult::OK;
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
Tracer::wait_for_tracee_events(Tid target_pid) noexcept
{
  auto tc = get_controller(target_pid);
  auto wait_res = tc->wait_pid(nullptr);
  if (!wait_res.has_value())
    return;
  auto wait = *wait_res;
  if (!tc->has_task(wait.waited_pid)) {
    tc->new_task(wait.waited_pid, true);
  }
  auto task = tc->register_task_waited(wait);
  tc->ptracestop_handler->handle_execution_event(task);
  // tc->handle_execution_event(task);
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
    SpinGuard lock{command_queue_lock};
    command_queue.push(cmd);
  }
#ifdef MDB_DEBUG
  logging::get_logging()->log("dap", fmt::format("accepted command {}", cmd->name()));
#endif
}

void
Tracer::execute_pending_commands() noexcept
{
  ui::UICommandPtr pending_command = nullptr;
  while (!command_queue.empty()) {
    // keep the lock as minimum of a time span as possible
    {
      SpinGuard lock{command_queue_lock};
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

void
Tracer::launch(bool stopAtEntry, Path &&program, std::vector<std::string> &&prog_args) noexcept
{
  std::vector<std::string> posix_cmd_args{};
  posix_cmd_args.push_back(program);
  for (auto &&arg : prog_args) {
    posix_cmd_args.push_back(arg);
  }
  PosixArgsList args_list{std::move(posix_cmd_args)};
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
    const auto [cmd, args] = args_list.get_command();
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
      PANIC("Failed to set ADDR_NO_RANDOMIZE!");
    }
    raise(SIGSTOP);
    if (execv(cmd, args) == -1) {
      PANIC(fmt::format("EXECV Failed for {}", cmd));
    }
    break;
  }
  default: {
    const auto res = get<PtyParentResult>(fork_result);
    add_target_set_current(res.pid, program, TargetSession::Launched);
    TaskInfo *t = get_current()->get_task(res.pid);
    for (;;) {
      if (const auto ws = waitpid_block(res.pid); ws) {
        const auto stat = ws->status;
        if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
          TaskWaitResult twr;
          twr.ws.ws = WaitStatusKind::Execed;
          twr.waited_pid = res.pid;
          DLOG("mdb", "Waited pid after exec! {}, previous: {}", twr.waited_pid, res.pid);
          t = get_current()->get_task(twr.waited_pid);
          ASSERT(t != nullptr, "Unknown task!!");
          get_current()->register_task_waited(twr);
          get_current()->reopen_memfd();
          get_current()->cache_registers(t);
          get_current()->read_auxv(t);
          get_current()->install_loader_breakpoints();
          dap->add_tty(res.fd);
          break;
        }
      }
      VERIFY(ptrace(PTRACE_CONT, res.pid, 0, 0) != -1, "Failed to continue passed our exec boundary");
      t->set_dirty();
      get_current()->reaped_events();
    }
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