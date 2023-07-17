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
#include "symbolication/cu.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
#include "target.h"
#include "task.h"
#include <algorithm>
#include <bits/ranges_util.h>
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

Tracer::Tracer(utils::Notifier::ReadEnd io_thread_pipe, utils::NotifyManager *events_notifier) noexcept
    : io_thread_pipe(io_thread_pipe), events_notifier(events_notifier)
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
  ASSERT(mmap_objectfile(objfile_path) == AddObjectResult::OK, "Failed to load object file");
  const auto obj_file = object_files.back();
  Elf::parse_objfile(obj_file);
  auto target = get_target(target_pid);
  target->register_object_file(obj_file);
  CompilationUnitBuilder cu_builder{obj_file};
  std::vector<std::unique_ptr<CUProcessor>> cu_processors{};
  auto total = cu_builder.build_cu_headers();
  std::vector<std::thread> jobs{};
  SpinLock stdio_lock{};

  for (auto &cu_hdr : total) {
    jobs.push_back(std::thread{[obj_file, cu_hdr, tgt = target, &stdio_lock]() {
      auto proc = prepare_cu_processing(obj_file, cu_hdr, tgt);
      auto compile_unit_die = proc->read_root_die();
      if (compile_unit_die->tag == DwarfTag::DW_TAG_compile_unit) {
        proc->process_compile_unit_die(compile_unit_die.get());
      } else {
        PANIC("Unexpected non-compile unit DIE parsed");
      }
      LockGuard guard{stdio_lock};
      fmt::println("Thread finished processing CU {}", cu_hdr.cu_index);
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
  targets.push_back(std::make_unique<Target>(task_leader, io_write, session, true));
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

Target *
Tracer::get_target(pid_t pid) noexcept
{
  auto it = std::ranges::find_if(targets, [&pid](auto &t) { return t->task_leader == pid; });
  ASSERT(it != std::end(targets), "Could not find target {} pid", pid);

  return it->get();
}

Target *
Tracer::get_current() noexcept
{
  return current_target;
}

void
Tracer::init_io_thread() noexcept
{
}

void
Tracer::interrupt(LWP lwp) noexcept
{
  auto target = get_target(lwp.pid);
  for (auto &task : target->threads) {
    if (!task.is_stopped()) {
      PTRACE_OR_PANIC(PTRACE_INTERRUPT, task.tid, nullptr, nullptr);
      task.set_stop();
      task.ptrace_stop = true;
    }
  }
}

bool
Tracer::wait_for_tracee_events(Tid target_pid) noexcept
{
  auto target = get_target(target_pid);
  auto wait_res = target->wait_pid(nullptr);
  if (!wait_res.has_value())
    return false;
  auto wait = *wait_res;
  // For now, we only support "all-stop" mode
  bool saw_task_before_parent_clone_return = false;
  bool stopped = false;
  if (!target->has_task(wait.waited_pid)) {
    target->new_task(wait.waited_pid, true);
    saw_task_before_parent_clone_return = true;
  }
  target->register_task_waited(wait);
  auto task = target->get_task(wait.waited_pid);
  task->stopped = true;
  switch (wait.ws) {
  case WaitStatus::Stopped: {
    target->cache_registers(task->tid);
    // some pretty involved functionality needs to be called here, I think.
    switch (target->handle_stopped_for(task)) {
    case ActionOnEvent::ShouldContinue: {
      // task->set_running(RunType::Continue);
      // stopped = false;
      break;
    }
    case ActionOnEvent::StopTracee: {
      target->is_in_user_ptrace_stop = true;
      stopped = true;
      for (auto &task : target->threads) {
        if (task.tid != wait.waited_pid &&
            (saw_task_before_parent_clone_return ? task.tid != target->task_leader : true)) {
          // peek wait statuses
          siginfo_t info_ptr;
          auto peek_waited_tid = waitid(P_PID, task.tid, &info_ptr, WEXITED | WSTOPPED | WNOWAIT | WNOHANG);
          // if task has no wait status waiting, it's most likely running
          // therefore we need to interrupt it.
          if (peek_waited_tid == 0) {
            VERIFY(-1 != tgkill(target->task_leader, task.tid, SIGSTOP), "Failed to send SIGSTOP to {}", task.tid);
            fmt::println("INTERRUPTING {}", task.tid);
            // we can block, because we know we sent this signal.
            siginfo_t info_ptr;
            const auto peek_waited_tid = waitid(P_PID, task.tid, &info_ptr, WEXITED | WSTOPPED | WNOHANG);
            fmt::println("SIGNO: {}", info_ptr.si_signo);
            task.ptrace_stop = true;
            target->is_in_user_ptrace_stop = true;
          } else {
            fmt::println("DID NOT INTERRUPT {}", task.tid);
            // task *was* stopped when we peeked - set stopped, but not by us
            task.stopped = true;
          }
        }
      }
      break;
    }
    }
  } break;
  case WaitStatus::Execed: {
    get_current()->reopen_memfd();
    target->cache_registers(task->tid);
    target->read_auxv(wait);
    break;
  }
  case WaitStatus::Exited: {
    target->reap_task(task);
    break;
  }
  case WaitStatus::Cloned: {
    // we always have to cache these registers, because we need them to pull out some information
    // about the new clone
    auto &registers = target->cache_registers(task->tid);
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(registers);
    const auto res = target->read_type(ptr);
    // Nasty way to get PID, but, in doing so, we also get stack size + stack location for new thread
    auto np = target->read_type(TPtr<pid_t>{res.parent_tid});
#ifdef MDB_DEBUG
    long new_pid = 0;
    PTRACE_OR_PANIC(PTRACE_GETEVENTMSG, wait.waited_pid, 0, &new_pid);
    ASSERT(np == new_pid, "Inconsistent pid values retrieved, expected {} but got {}", np, new_pid);
#endif
    if (!target->has_task(np)) {
      target->new_task(np, true);
    }
    // by this point, the task has cloned _and_ it's continuable because the parent has been told
    // that "hey, we're ok". Why on earth a pre-finished clone can be waited on, I will never know.
    target->get_task(np)->initialize();
    // task backing storage may have re-allocated and invalidated this pointer.
    task = target->get_task(wait.waited_pid);
    target->set_task_vm_info(np, TaskVMInfo::from_clone_args(res));
    for (const auto bp : target->user_brkpts.breakpoints) {
      auto read_value = ptrace(PTRACE_PEEKDATA, np, bp.address.get(), nullptr);
      u8 ins_byte = static_cast<u8>(read_value & 0xff);
      fmt::println("Byte at breakpoint addr in {} is {}", np, ins_byte);
    }
    if (target->should_stop_on_clone() || target->is_in_user_ptrace_stop) {
      stopped = true;
      target->is_in_user_ptrace_stop = true;
      target->cache_registers(np);
      for (auto &task : target->threads) {
        if (task.tid != wait.waited_pid && task.tid != np) {
          int stat;
          // peek wait statuses
          const auto peek = waitpid_peek(task.tid);
          // if task has no wait status waiting, it's most likely running
          // therefore we need to interrupt it.
          if (!peek) {
            PTRACE_OR_PANIC(PTRACE_INTERRUPT, task.tid, nullptr, nullptr);
            // we can block, because we know we sent this signal.
            fmt::println("TRACER WAITPID");
            task.ptrace_stop = true;
          } else {
            // task *was* stopped when we peeked - set stopped, but not by us
            task.stopped = true;
          }
        }
      }
    } else {
      if (!target->is_in_user_ptrace_stop) {
        fmt::println("CONTINUING AFTER CLONE MOTHERFUCKER");
        task->set_running(RunType::Continue);
      }
    }

    break;
  }
  case WaitStatus::Forked:
    break;
  case WaitStatus::VForked:
    break;
  case WaitStatus::VForkDone:
    break;
  case WaitStatus::Signalled:
    task->stopped = true;
    break;
  case WaitStatus::SyscallEntry:
    break;
  case WaitStatus::SyscallExit:
    break;
  default:
    stopped = false;
  }

  target->reaped_events();
  return stopped;
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
    auto result = pending_command->execute(this);

    dap->post_event(result);
    delete pending_command;
    pending_command = nullptr;
  }
}

void
Tracer::launch(Path &&program, std::vector<std::string> &&prog_args) noexcept
{
  std::vector<std::string> posix_cmd_args{};
  posix_cmd_args.push_back(program);
  for (auto &&arg : prog_args) {
    posix_cmd_args.push_back(arg);
  }
  PosixArgsList args_list{std::move(posix_cmd_args)};
  termios original_tty;
  winsize ws;
  VERIFY(tcgetattr(STDIN_FILENO, &original_tty) != -1, "Failed to get attributes for stdin");
  VERIFY(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0, "Failed to get winsize of stdin");

  auto fork_result = pty_fork(&original_tty, &ws);
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
  }
  default: {
    const auto res = get<PtyParentResult>(fork_result);
    add_target_set_current(res.pid, program, TargetSession::Launched);

    for (;;) {
      if (const auto ws = waitpid_block(res.pid); ws) {
        const auto stat = ws->status;
        if ((stat >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
          TaskWaitResult twr;
          twr.ws = WaitStatus::Execed;
          twr.waited_pid = res.pid;
          get_current()->reopen_memfd();
          get_current()->cache_registers(twr.waited_pid);
          get_current()->read_auxv(twr);
          dap->add_tty(res.fd);
          break;
        }
      }
      VERIFY(ptrace(PTRACE_CONT, res.pid, 0, 0) != -1, "Failed to continue passed our exec boundary");
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
Tracer::detach(std::unique_ptr<Target> &&target) noexcept
{
  // we have taken ownership of `target` in this "sink". Target will be destroyed (should be?)
  target->detach();
}