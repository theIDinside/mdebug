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
#include <fcntl.h>
#include <filesystem>
#include <ranges>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>

Tracer *Tracer::Instance = nullptr;

Tracer::Tracer() noexcept
{
  ASSERT(Tracer::Instance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)Instance);
  Instance = this;
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
  targets.push_back(std::make_unique<Target>(task_leader, true));
  current_target = targets.back().get();
  load_and_process_objfile(task_leader, path);
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