#pragma once
#include "breakpoint.h"
#include "common.h"
#include "lib/spinlock.h"
#include "symbolication/type.h"
#include "task.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>

namespace ui {
struct UICommand;
};

struct LWP
{
  Pid pid;
  Tid tid;

  constexpr bool operator<=>(const LWP &other) const = default;
};

enum ActionOnEvent
{
  ShouldContinue,
  StopTracee
};

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

struct Target;

struct BreakpointMap
{
  u32 bp_id_counter;
  std::vector<Breakpoint> breakpoints;
  std::unordered_map<u32, std::string> fn_breakpoint_names;
  std::unordered_map<u32, std::string> source_breakpoints;

  template <typename T>
  bool
  contains(TraceePointer<T> addr) const noexcept
  {
    return any_of(breakpoints, [&addr](const Breakpoint &bp) { return bp.address == addr; });
  }
  bool insert(TraceePointer<void> addr, u8 overwritten_byte, BreakpointType type) noexcept;
  void clear(Target *target, BreakpointType type) noexcept;

  template <typename Predicate> friend void clear_breakpoints(BreakpointMap &bp, Target *, Predicate &&p) noexcept;

  Breakpoint *get(u32 id) noexcept;
  Breakpoint *get(TraceePointer<void> addr) noexcept;
};

struct Target
{
  friend class Tracer;
  friend struct ui::UICommand;
  // Members
  pid_t task_leader;
  std::vector<ObjectFile *> object_files;
  ScopedFd procfs_memfd;
  std::vector<TaskInfo> threads;
  std::unordered_map<pid_t, TaskVMInfo> task_vm_infos;
  BreakpointMap user_breakpoints_map;
  bool stop_on_clone;

  // Aggressive spinlock
  SpinLock spin_lock;

  // Constructors
  Target(pid_t process_space_id, bool open_mem_fd = true) noexcept;
  Target(const Target &) = delete;
  Target &operator=(const Target &) = delete;

  /** Re-open proc fs mem fd. In cases where task has exec'd, for instance. */
  bool reopen_memfd() noexcept;
  /** Return the open mem fd */
  ScopedFd &mem_fd() noexcept;
  TaskInfo *get_task(pid_t pid) noexcept;
  /* wait on `task` or the entire target if `task` is nullptr */
  std::optional<TaskWaitResult> wait_pid(TaskInfo *task) noexcept;
  /* Create new task meta data for `tid` */
  void new_task(Tid tid) noexcept;
  bool has_task(Tid tid) noexcept;
  /* Set all tasks in this target to continue, if they're stopped. */
  void set_all_running(RunType type) noexcept;
  /* Interrupts/stops all threads in this process space */
  void stop_all() noexcept;
  /* Query if we should interrupt the entire process and all it's tasks when we encounter a clone syscall */
  bool should_stop_on_clone() noexcept;
  /* Perform arbitrary logic during a Stopped event */
  ActionOnEvent handle_stopped_for(TaskInfo *task) noexcept;
  /* Handle when a task exits or dies, so that we collect relevant meta data about it and also notifies the user
   * interface of the event */
  void reap_task(TaskInfo *task) noexcept;
  /** We've gotten a `TaskWaitResult` and we want to register it with the task it's associated with. This also
   * reads that task's registers and caches them.*/
  void register_task_waited(TaskWaitResult wait) noexcept;

  /** Set a task's virtual memory info, which for now involves the stack size for a task as well as it's stack
   * address. These are parameters known during the `clone` syscall and we will need them to be able to restore a
   * task, later on.*/
  void set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept;
  /* Cache the register contents of `tid`. */
  [[maybe_unused]] const user_regs_struct &cache_registers(Tid tid) noexcept;
  /* Set breakpoint att tracee `address`. If a breakpoint is already set there, we do nothing. We don't allow for
   * multiple breakpoints at the same location.*/
  void set_addr_breakpoint(TraceePointer<u64> address) noexcept;
  void set_fn_breakpoint(std::string_view function_name) noexcept;
  void emit_stopped_at_breakpoint(LWP lwp, TPtr<void> bp_addr);

  // TODO(simon): major optimization can be done. We naively remove all breakpoints and the set
  //  what's in `addresses`. Why? because the stupid DAP doesn't do smart work and forces us to
  // to do it. But since we're not interested in solving this particular problem now, we'll do the stupid
  // thing
  void reset_addr_breakpoints(std::vector<TPtr<void>> addresses) noexcept;
  void reset_fn_breakpoints(std::vector<std::string_view> fn_names) noexcept;

  // todo(simon): These need re-factoring. They're only confusing as hell and misleading.
  void task_wait_emplace(int status, TaskWaitResult *wait) noexcept;
  void task_wait_emplace_stopped(int status, TaskWaitResult *wait) noexcept;
  void task_wait_emplace_signalled(int status, TaskWaitResult *wait) noexcept;
  void task_wait_emplace_exited(int status, TaskWaitResult *wait) noexcept;

  /* Check if we have any tasks left in the process space. */
  bool running() const noexcept;

  // Debug Symbols Related Logic
  void register_object_file(ObjectFile *obj) noexcept;

  // we pass TaskWaitResult here, because want to be able to ASSERT that we just exec'ed.
  // because we actually need to be at the *first* position on the stack, which, if we do at any other time we
  // might (very likely) not be.
  void read_auxv(TaskWaitResult &wait);

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
  T
  read_type(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type result;
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    while (total_read < sz) {
      auto read_bytes = pread64(mem_fd().get(), &result + total_read, sz - total_read, address.get());
      if (-1 == read_bytes || 0 == read_bytes) {
        PANIC(fmt::format("Failed to proc_fs read from {:p}", (void *)address.get()));
      }
      total_read += read_bytes;
    }
    return result;
  }

  template <typename T>
  T
  cache_and_overwrite(TraceePointer<T> address, T &value)
  {
    auto old_value = read_type(address);
    auto total_written = 0ull;
    constexpr auto sz = sizeof(typename TPtr<T>::Type);
    while (total_written < sz) {
      auto written = pwrite64(mem_fd().get(), &value, sz, address.get());
      if (-1 == written || 0 == written) {
        PANIC(fmt::format("Failed to proc_fs write to {:p}", (void *)address.get()));
      }
      total_written += written;
    }
    return old_value.value();
  }

  template <typename T>
  void
  write(TraceePointer<T> address, T &value)
  {
    auto total_written = 0ull;
    constexpr auto sz = address.type_size();
    while (total_written < sz) {
      auto written = pwrite64(mem_fd().get(), &value, sz, address.get());
      if (-1 == written || 0 == written) {
        PANIC(fmt::format("Failed to proc_fs write to {:p}", (void *)address.get()));
      }
      total_written += written;
    }
  }

  template <typename T>
  std::optional<T>
  read_type_readv(TraceePointer<T> address, pid_t pid)
  {
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

  /* Add parsed DWARF debug info for `file` */
  void add_file(CompilationUnitFile &&file) noexcept;
  /* Add parsed DWARF debug info for `type` */
  void add_type(Type type) noexcept;

private:
  std::vector<CompilationUnitFile> m_files;
  std::unordered_map<std::string_view, Type> m_types;
  std::optional<TPtr<void>> interpreter_base;
  std::optional<TPtr<void>> entry;
  std::unordered_map<Tid, user_regs_struct> register_cache;
};

template <typename Predicate>
void
clear_breakpoints(BreakpointMap &bp, Target *target, Predicate &&predicate) noexcept
{
  std::erase_if(bp.breakpoints, [target, &p = predicate](auto &bp) {
    if (p(bp)) {
      ptrace(PTRACE_POKEDATA, target->task_leader, bp.second.address.get(), bp.second.ins_byte);
      return true;
    }
  });
}