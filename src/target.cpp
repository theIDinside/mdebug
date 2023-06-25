#include "target.h"
#include "common.h"
#include <fcntl.h>
#include <filesystem>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>

ObjectFile::ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), size(size), loaded_binary(loaded_binary)
{
}

ObjectFile::~ObjectFile() noexcept { munmap((void *)loaded_binary, size); }

Target::Target(u16 global_id, pid_t process_space_id, Path path, ObjectFile *obj, bool open_mem_fd) noexcept
    : global_target_id(global_id), task_leader(process_space_id), path(path), obj_file(obj), threads{}
{
  threads[process_space_id] = {.tid = process_space_id};
  if (open_mem_fd) {
    const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
    procfs_memfd = ScopedFd::open(procfs_path, O_RDONLY);
  }
}

Target::Target(Target &&other) noexcept
    : global_target_id(other.global_target_id), task_leader(other.task_leader), path(std::move(other.path)),
      obj_file(other.obj_file), procfs_memfd(std::move(other.procfs_memfd)), threads{std::move(other.threads)}
{
}

bool
Target::initialized() const noexcept
{
  return !(obj_file == nullptr);
}

bool
Target::reopen_memfd() noexcept
{
  const auto procfs_path = fmt::format("/proc/{}/task/{}/mem", task_leader, task_leader);
  procfs_memfd = ScopedFd::open(procfs_path, O_RDONLY);
  return procfs_memfd.is_open();
}

ScopedFd& Target::mem_fd() noexcept {
  return procfs_memfd;
}
