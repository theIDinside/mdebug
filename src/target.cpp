#include "target.h"
#include "common.h"
#include "ptrace.h"
#include "task.h"
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

Target::Target(pid_t process_space_id, Path path, ObjectFile *obj, bool open_mem_fd) noexcept
    : task_leader(process_space_id), path(path), obj_file(obj), threads{}
{
  threads[process_space_id] = TaskInfo{process_space_id, nullptr};
  if (open_mem_fd) {
    const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
    procfs_memfd = ScopedFd::open(procfs_path, O_RDONLY);
  }
}

Target::Target(Target &&other) noexcept
    : task_leader(other.task_leader), path(std::move(other.path)), obj_file(other.obj_file),
      procfs_memfd(std::move(other.procfs_memfd)), threads{std::move(other.threads)}
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

ScopedFd &
Target::mem_fd() noexcept
{
  return procfs_memfd;
}

TaskInfo *
Target::get_task(pid_t pid) noexcept
{
  return &threads[pid];
}

TaskWaitResult
Target::wait_pid(TaskInfo *task) noexcept
{
  int status = 0;
  TaskWaitResult wait{};
  auto wait_tid = task == nullptr ? 0 : task->tid;
  wait.waited_pid = waitpid(wait_tid, &status, 0);
  task_wait_emplace(status, &wait);
  return wait;
}

void
Target::new_task(Tid tid) noexcept
{
  if constexpr (MDB_DEBUG) {
    fmt::println("New task {} (thread parent: {})", tid, task_leader);
  }

  threads[tid] = TaskInfo{ tid, nullptr };
}

void
Target::set_running(RunType type) noexcept
{
  threads[task_leader].set_running(type);
}

void
Target::set_wait_status(TaskWaitResult wait) noexcept
{
  ASSERT(threads.contains(wait.waited_pid), "Target did not contain task {}", wait.waited_pid);
  threads[wait.waited_pid].set_taskwait(wait);
}

void
Target::set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept
{
  ASSERT(threads.contains(tid), "Unknown task {}", tid);
  task_vm_infos[tid] = vm_info;
}