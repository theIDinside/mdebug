#include "tracer.h"
#include "common.h"
#include "ptrace.h"
#include "target.h"
#include <fcntl.h>
#include <filesystem>
#include <sys/mman.h>
#include <sys/stat.h>

Tracer::Tracer() noexcept {}

void
Tracer::add_target(pid_t task_leader, const Path &path) noexcept
{
  new_target_set_options(task_leader);
  ObjectFile *obj_file = nullptr;
  switch (add_object_file(path)) {
  case AddObjectResult::OK:
    obj_file = object_files.back();
    break;
  case AddObjectResult::MMAP_FAILED:
    panic(fmt::format("Failed to load binary '{}' into memory - debugging will be impossible.", path.c_str()));
    break;
  case AddObjectResult::FILE_NOT_EXIST:
    panic(fmt::format("File {} does not exist", path.c_str()));
    break;
  }
  fmt::println("adding target {}", task_leader);
  targets.push_back(Target{static_cast<u16>(task_leader), task_leader, path, obj_file});
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
Tracer::new_thread(Pid pid, Tid tid) noexcept {
  for(auto& tgt : targets) {
    if(tgt.task_leader == pid) {
      fmt::println("Adding thread {} to process space {}", tid, pid);
      tgt.threads[tid] = {.tid = tid};
    }
  }
}

void Tracer::thread_exited(Tid tid, int) noexcept {
  for(auto& tgt : targets) {
    if(tgt.threads.contains(tid)) {
      tgt.threads.erase(tid);
    }
  }
}

Target& Tracer::get_target(pid_t pid) noexcept {
  for(auto& t : targets) {
    if(t.task_leader == pid) {
      return t;
    }
    if(t.threads.contains(pid)) return t;
  }
  panic(fmt::format("No target with id {}", pid));
  return *(Target*)nullptr;
}