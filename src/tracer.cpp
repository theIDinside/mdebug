#include "tracer.h"
#include "./interface/dap/interface.h"
#include "common.h"
#include "interface/dap/events.h"
#include "interface/ui_command.h"
#include "interface/ui_result.h"
#include "lib/lockguard.h"
#include "lib/spinlock.h"
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
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

Tracer *Tracer::Instance = nullptr;

Tracer::Tracer() noexcept
{
  ASSERT(Tracer::Instance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)Instance);
  Instance = this;
  ui_wait = true;
  this->command_queue = {};
}

void
Tracer::load_and_process_objfile(pid_t target_pid, const Path &objfile_path) noexcept
{
  ASSERT(mmap_objectfile(objfile_path) == AddObjectResult::OK, "Failed to load object file");
  const auto obj_file = object_files.back();
  Elf::parse_objfile(obj_file);
  auto &target = get_target(target_pid);
  target.register_object_file(obj_file);
  CompilationUnitBuilder cu_builder{obj_file};
  std::vector<std::unique_ptr<CUProcessor>> cu_processors{};
  auto total = cu_builder.build_cu_headers();
  std::vector<std::thread> jobs{};
  SpinLock stdio_lock{};

  for (auto &cu_hdr : total) {
    jobs.push_back(std::thread{[obj_file, cu_hdr, tgt = get_current(), &stdio_lock]() {
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
Tracer::add_target_set_current(pid_t task_leader, const Path &path) noexcept
{
  static pid_t leader_kill = task_leader;
  targets.push_back(std::make_unique<Target>(task_leader, true));
  auto evt = new ui::dap::OutputEvent{
      "console"sv, fmt::format("Task ({}) {} created (task leader: {})", 1, task_leader, task_leader)};
  Tracer::Instance->post_event(evt);
  current_target = targets.back().get();
  load_and_process_objfile(task_leader, path);
  PTRACE_OR_PANIC(PTRACE_SEIZE, task_leader, 0, 0);
  new_target_set_options(task_leader);
  atexit([]() { ptrace(PTRACE_KILL, leader_kill, 0, 0); });
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
Tracer::new_task(Pid pid, Tid tid) noexcept
{
  auto it = std::find_if(targets.cbegin(), targets.cend(), [&pid](auto &t) { return t->task_leader = pid; });
  ASSERT(it != std::end(targets), "Did not find target with task leader {} pid", pid);
  it->get()->new_task(tid);
}

void
Tracer::thread_exited(LWP lwp, int) noexcept
{
  auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Exited, lwp.tid};
  dap->post_event(evt);
}

Target &
Tracer::get_target(pid_t pid) noexcept
{
  auto it = std::ranges::find_if(targets, [&pid](auto &t) { return t->task_leader == pid; });
  ASSERT(it != std::end(targets), "Could not find target {} pid", pid);

  return **it;
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
  auto &target = get_target(lwp.pid);
  for (auto &task : target.threads) {
    if (!task.is_stopped()) {
      PTRACE_OR_PANIC(PTRACE_INTERRUPT, task.tid, nullptr, nullptr);
      task.set_stop();
      task.stopped_by_tracer = true;
    }
  }
}

bool
Tracer::waiting_for_ui() const noexcept
{
  return ui_wait;
}
void
Tracer::continue_current_target() noexcept
{
  char ch;
  // Emulating user input to say "continue" by just typing a character
  ASSERT(read(STDIN_FILENO, &ch, 1) != -1, "Failed to read from STDIN: {}", strerror(errno));
  ui_wait = false;
  get_current()->set_all_running(RunType::Continue);
}

bool
Tracer::wait_for_tracee_events() noexcept
{
  auto target = get_current();
  auto wait_res = target->wait_pid(nullptr);
  if (!wait_res.has_value())
    return false;
  auto wait = *wait_res;
  // For now, we only support "all-stop" mode
  bool do_not_interrupt_leader = false;
  bool stopped = false;
  if (!target->has_task(wait.waited_pid)) {
    target->new_task(wait.waited_pid);
    do_not_interrupt_leader = true;
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
      task->set_running(RunType::Continue);
      break;
    }
    case ActionOnEvent::StopTracee: {
      stopped = true;
      for (auto &task : target->threads) {
        if (task.tid != wait.waited_pid && (do_not_interrupt_leader ? task.tid != target->task_leader : true)) {
          int stat;
          // peek wait statuses
          const auto peek_waited_tid = waitpid(task.tid, &stat, WNOHANG | WNOWAIT);
          // if task has no wait status waiting, it's most likely running
          // therefore we need to interrupt it.
          if (peek_waited_tid == 0) {
            PTRACE_OR_PANIC(PTRACE_INTERRUPT, task.tid, nullptr, nullptr);
            // we can block, because we know we sent this signal.
            waitpid(task.tid, &stat, 0);
            task.stopped_by_tracer = true;
          } else {
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
      target->new_task(np);
    }
    // by this point, the task has cloned _and_ it's continuable because the parent has been told
    // that "hey, we're ok". Why on earth a pre-finished clone can be waited on, I will never know.
    target->get_task(np)->initialize();
    // task backing storage may have re-allocated and invalidated this pointer.
    task = target->get_task(wait.waited_pid);
    target->set_task_vm_info(np, TaskVMInfo::from_clone_args(res));
    if (target->should_stop_on_clone()) {
      stopped = true;
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
            waitpid(task.tid, &stat, 0);
            task.stopped_by_tracer = true;
          } else {
            // task *was* stopped when we peeked - set stopped, but not by us
            task.stopped = true;
          }
        }
      }
    } else {
      task->set_running(RunType::Continue);
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
    PANIC("WAIT, WHAT?");
  }
  ui_wait = true;
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