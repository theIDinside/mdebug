#include "tracer.h"
#include "common.h"
#include "lib/lockguard.h"
#include "ptrace.h"
#include "symbolication/cu.h"
#include "symbolication/dwarf.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
#include "target.h"
#include <algorithm>
#include <bits/ranges_util.h>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <ranges>
#include <sys/mman.h>
#include <sys/stat.h>
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
  current_target = targets.back().get();
  load_and_process_objfile(task_leader, path);
  new_target_set_options(task_leader);
  fmt::println("New process: {}", task_leader);
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
  it->get()->threads[tid] = TaskInfo{tid, nullptr};
}

void
Tracer::thread_exited(LWP lwp, int) noexcept
{
  auto &t = get_target(lwp.pid);
  t.threads.erase(lwp.tid);
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
  fmt::println("IO Thread Not Implemented");
}

bool
Tracer::waiting_for_ui() const noexcept
{
  return ui_wait;
}
void
Tracer::wait_and_process_ui_events() noexcept
{
  char ch;
  ASSERT(read(STDIN_FILENO, &ch, 1) != -1, "Failed to read from STDIN: {}", strerror(errno));
  ui_wait = false;
  fmt::println("Continuing...");
  get_current()->set_running(RunType::Continue);
}

void
Tracer::wait_for_tracee_events() noexcept
{
  auto target = get_current();
  auto current_task = target->get_task(target->task_leader);
  auto tracee_exited = false;
  // while (!tracee_exited) {
  auto wait = target->wait_pid(current_task);
  target->set_wait_status(wait);
  switch (wait.ws) {
  case WaitStatus::Stopped:
    break;
  case WaitStatus::Execed: {
    get_current()->reopen_memfd();
    target->read_auxv(wait);
    break;
  }
  case WaitStatus::Exited: {
    if (wait.waited_pid == get_current()->task_leader) {
      tracee_exited = true;
    }
    break;
  }
  case WaitStatus::Cloned: {
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(wait.registers);
    const auto res = target->read_type(ptr);
    // Nasty way to get PID, but, in doing so, we also get stack size + stack location for new thread
    auto np = target->read_type(TPtr<pid_t>{res.parent_tid});
#ifdef MDB_DEBUG
    long new_pid = 0;
    PTRACE_OR_PANIC(PTRACE_GETEVENTMSG, wait.waited_pid, 0, &new_pid);
    ASSERT(np == new_pid, "Inconsistent pid values retrieved, expected {} but got {}", np, new_pid);
#endif
    target->new_task(np);
    target->set_task_vm_info(np, TaskVMInfo::from_clone_args(res));
    target->get_task(np)->request_registers();
    break;
  }
  case WaitStatus::Forked:
    break;
  case WaitStatus::VForked:
    break;
  case WaitStatus::VForkDone:
    break;
  case WaitStatus::Signalled:
    break;
  case WaitStatus::SyscallEntry:
    break;
  case WaitStatus::SyscallExit:
    break;
  }
  ui_wait = true;
  // }
}