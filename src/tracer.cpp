#include "tracer.h"
#include "common.h"
#include "ptrace.h"
#include "symbolication/cu.h"
#include "symbolication/dwarf.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
#include "target.h"
#include <fcntl.h>
#include <filesystem>
#include <sys/mman.h>
#include <sys/stat.h>

Tracer *Tracer::Instance = nullptr;

Tracer::Tracer() noexcept
{
  ASSERT(Tracer::Instance == nullptr,
         "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
         (uintptr_t)this, (uintptr_t)Instance);
  Instance = this;
}

void
Tracer::add_target(pid_t task_leader, const Path &path) noexcept
{
  ObjectFile *obj_file = nullptr;
  switch (add_object_file(path)) {
  case AddObjectResult::OK:
    obj_file = object_files.back();
    break;
  case AddObjectResult::MMAP_FAILED:
    PANIC(fmt::format("Failed to load binary '{}' into memory - debugging will be impossible.", path.c_str()));
    break;
  case AddObjectResult::FILE_NOT_EXIST:
    PANIC(fmt::format("File {} does not exist", path.c_str()));
    break;
  }
  ASSERT(obj_file != nullptr, "Object file can't be nullptr");

  auto elf = Elf::parse_objfile(obj_file);
  targets.emplace(task_leader, Target{task_leader, path, obj_file});
  auto &target = get_target(task_leader);

  CompilationUnitBuilder cu_builder{obj_file};
  std::vector<std::unique_ptr<CUProcessor>> cu_processors{};
  auto total = cu_builder.build_cu_headers();
  for (const auto &cu_hdr : total) {
    cu_processors.emplace_back(prepare_cu_processing(obj_file, cu_hdr, get_current()));
  }

  std::vector<File> files;
  std::vector<std::unique_ptr<DebugInfoEntry>> compile_unit_dies{};
  for (auto &proc : cu_processors) {
    auto compile_unit_die = proc->read_root_die();
    if (compile_unit_die->tag == DwarfTag::DW_TAG_compile_unit) {
      proc->process_compile_unit_die(compile_unit_die.get());
    } else {
      PANIC("Unexpected non-compile unit DIE parsed");
    }
    compile_unit_dies.push_back(std::move(compile_unit_die));
  }
  target.elf = elf;
  target.minimal_symbols = target.elf->parse_min_symbols();
  current_target = &targets[task_leader];
  new_target_set_options(task_leader);
  for (const auto &f : files) {
    get_current()->add_file(f);
  }
}

AddObjectResult
Tracer::add_object_file(const Path &path) noexcept
{
  if (!fs::exists(path))
    return AddObjectResult::FILE_NOT_EXIST;

  auto fd = ScopedFd::open_read_only(path);
  const auto addr = (u8 *)mmap(nullptr, fd.file_size(), PROT_READ, MAP_PRIVATE, fd.get(), 0);
  if (addr == MAP_FAILED) {
    fmt::println("Failed to open file {} ({}) with size {}", path.c_str(), fd.get(), fd.file_size());
    return AddObjectResult::MMAP_FAILED;
  }

  auto obj = new ObjectFile{path, fd.file_size(), addr};
  object_files.push_back(obj);

  return AddObjectResult::OK;
}

void
Tracer::new_task(Pid pid, Tid tid) noexcept
{
  targets[pid].threads[tid] = TaskInfo{tid, nullptr};
}

void
Tracer::thread_exited(Tid tid, int) noexcept
{
  for (auto &[pid, tgt] : targets) {
    if (tgt.threads.contains(tid)) {
      tgt.threads.erase(tid);
    }
  }
}

Target &
Tracer::get_target(pid_t pid) noexcept
{
#ifdef MDB_DEBUG
  if (!targets.contains(pid)) {
    PANIC(fmt::format("Target {} does not exist", pid));
  }
#endif
  return targets[pid];
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