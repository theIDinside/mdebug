#pragma once
#include "common.h"
#include "task.h"
#include <cstdint>
#include <cstdio>
#include <optional>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>
#include <unordered_map>

using Tid = pid_t;
using Pid = pid_t;

using Address = std::uintptr_t;
struct ObjectFile;

template <typename T>
static ssize_t
read_bytes_ptrace(TraceePointer<T> addr, ssize_t buf_size, void *buf, pid_t tid)
{
  ssize_t nread = 0;
  // ptrace operates on the word size of the host, so we really do want
  // to use sizes of host types here.
  uintptr_t word_size = sizeof(long);
  errno = 0;
  // Only read aligned words. This ensures we can always read the last
  // byte before an unmapped region.
  while (nread < buf_size) {
    uintptr_t start = addr.get() + nread;
    uintptr_t start_word = start & ~(word_size - 1);
    uintptr_t end_word = start_word + word_size;
    uintptr_t length = std::min(end_word - start, uintptr_t(buf_size - nread));
    long v = ptrace(PTRACE_PEEKDATA, tid, start_word, nullptr);
    if (errno) {
      break;
    }
    memcpy(static_cast<uint8_t *>(buf) + nread, reinterpret_cast<uint8_t *>(&v) + (start - start_word), length);
    nread += length;
  }

  return nread;
}

struct Target
{
  // Members
  pid_t task_leader;
  Path path;
  ObjectFile *obj_file;
  ScopedFd procfs_memfd;
  std::unordered_map<pid_t, TaskInfo> threads;
  std::unordered_map<pid_t, TaskVMInfo> task_vm_infos;

  // Constructors
  Target() = default;
  Target(pid_t process_space_id, Path path, ObjectFile *obj, bool open_mem_fd = true) noexcept;
  Target(Target &&other) noexcept;

  // Methods
  bool initialized() const noexcept;
  /** Re-open proc fs mem fd. In cases where task has exec'd, for instance. */
  bool reopen_memfd() noexcept;
  /** Return the open mem fd */
  ScopedFd &mem_fd() noexcept;
  TaskInfo *get_task(pid_t pid) noexcept;
  TaskWaitResult wait_pid(TaskInfo *task) noexcept;
  void new_task(Tid tid) noexcept;
  void set_running(RunType type) noexcept;
  void set_wait_status(TaskWaitResult wait) noexcept;
  void set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept;

  template <typename T>
  std::optional<T>
  read_type_ptrace(TraceePointer<T> address, pid_t pid)
  {
    typename std::remove_cv<T>::type result;
    constexpr u64 sz = sizeof(T);
    auto ptrace_read = read_bytes_ptrace(address, sz, &result, pid);
    if (ptrace_read != sz) {
      fmt::println("Failed to read {} bytes (read {})", ptrace_read, sz);
      return {};
    } else {
      return result;
    }
  }

  template <typename T>
  std::optional<T>
  read_type(TraceePointer<T> address)
  {
    typename std::remove_cv<T>::type result;
    auto total_read = 0ull;
    constexpr u64 sz = sizeof(T);
    while (total_read < sz) {
      auto read_bytes = pread64(mem_fd().get(), &result + total_read, sizeof(T) - total_read, address.get());
      if (-1 == read_bytes || 0 == read_bytes) {
        PANIC(fmt::format("Failed to proc_fs read from {:p}", (void*)address.get()));
      }
      total_read += read_bytes;
    }
    return result;
  }

  template <typename T>
  std::optional<T>
  read_type_readv(TraceePointer<T> address, pid_t pid)
  {
    fmt::println("[read_type_readv] Reading from address 0x{:x}", address.get());
    typename std::remove_cv<T>::type result;
    constexpr u64 sz = sizeof(T);
    struct iovec io;
    struct iovec remote;
    remote.iov_base = (void *)address.get();
    remote.iov_len = sz;

    // Read data from child process memory
    io.iov_base = &result;
    io.iov_len = sz;
    ssize_t bytes_read = process_vm_readv(pid, &io, 1, &remote, 1, 0);
    if (bytes_read != sz) {
      fmt::println("Failed to read {} bytes, read {}", sz, bytes_read);
      return {};
    } else {
      fmt::println("Successfully process_vm_readv");
      return result;
    }
  }
};