#pragma once
#include "awaiter.h"
#include "breakpoint.h"
#include "common.h"
#include "lib/spinlock.h"
#include "symbolication/callstack.h"
#include "symbolication/elf.h"
#include "symbolication/type.h"
#include "task.h"
#include "utils/static_vector.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

namespace ptracestop {
class StopHandler;
class Action;
} // namespace ptracestop

namespace ui {
struct UICommand;
};

struct LWP
{
  Pid pid;
  Tid tid;

  constexpr bool operator<=>(const LWP &other) const = default;
};

enum class TracerWaitEvent : u8
{
  BreakpointHit,
  WatchpointHit,
  None,
};

struct WE
{
  TracerWaitEvent event;
  union
  {
    AddrPtr pc;
    Breakpoint *bp;
    struct
    {
      AddrPtr var_addr;
      u64 new_value;
    } watchpoint;
  };
};

struct SearchFnSymResult
{
  const FunctionSymbol *fn_sym;
  const CompilationUnitFile *cu_file;
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

struct TraceeController;

struct BreakpointMap
{
  struct TaskBreakpointStatus
  {
    Tid tid;
    u16 bp_id;
    bool stepped_over;
  };

  explicit BreakpointMap(Tid address_space) noexcept
      : bp_id_counter(1), breakpoints(), address_space_tid(address_space), fn_breakpoint_names(),
        source_breakpoints(), task_bp_stats()
  {
  }

  u32 bp_id_counter;
  // All breakpoints are stored in `breakpoints` - and they map to either `fn_breakpoint_names` or
  // `source_breakpoints` depending on their type (or to neither - if they're address breakpoints). So we don't
  // allow for multiple breakpoints on the same loc, because I argue it's a bad decision that makes breakpoint
  // design much more complex for almost 0 gain.
  std::vector<Breakpoint> breakpoints;
  Tid address_space_tid;
  std::unordered_map<u32, std::string> fn_breakpoint_names;
  std::unordered_map<u32, SourceBreakpointDescriptor> source_breakpoints;
  // Task's breakpoint statuses. Information about regarding the relationship between a hit breakpoint and a task
  std::vector<TaskBreakpointStatus> task_bp_stats;

  template <typename T>
  bool
  contains(TraceePointer<T> addr) const noexcept
  {
    return any_of(breakpoints, [&addr](const Breakpoint &bp) { return bp.address == addr; });
  }

  void add_bpstat_for(TaskInfo *t, Breakpoint *bp);
  bool insert(TraceePointer<void> addr, u8 overwritten_byte, BreakpointType type) noexcept;
  void clear(TraceeController *target, BreakpointType type) noexcept;
  void clear_breakpoint_stats() noexcept;
  void disable_breakpoint(u16 id) noexcept;
  void enable_breakpoint(u16 id) noexcept;

  Breakpoint *get_by_id(u32 id) noexcept;
  Breakpoint *get(TraceePointer<void> addr) noexcept;
};

class Default;

struct TraceeController
{
  using handle = std::unique_ptr<TraceeController>;
  friend class Tracer;
  friend struct ui::UICommand;
  // Members
  pid_t task_leader;
  std::vector<ObjectFile *> object_files;
  ScopedFd procfs_memfd;
  std::vector<TaskInfo> threads;
  std::unordered_map<pid_t, TaskVMInfo> task_vm_infos;
  BreakpointMap user_brkpts;
  bool stop_on_clone;

  // Aggressive spinlock
  SpinLock spin_lock;

  // Constructors
  TraceeController(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify, TargetSession session,
                   bool open_mem_fd = true) noexcept;
  TraceeController(const TraceeController &) = delete;
  TraceeController &operator=(const TraceeController &) = delete;

  /** Re-open proc fs mem fd. In cases where task has exec'd, for instance. */
  bool reopen_memfd() noexcept;
  /** Return the open mem fd */
  ScopedFd &mem_fd() noexcept;
  TaskInfo *get_task(pid_t pid) noexcept;
  /* wait on `task` or the entire target if `task` is nullptr */
  std::optional<TaskWaitResult> wait_pid(TaskInfo *task) noexcept;
  /* Create new task meta data for `tid` */
  void new_task(Tid tid, bool ui_update) noexcept;
  bool has_task(Tid tid) noexcept;
  /* Resumes all tasks in this target. */
  void resume_target(RunType type) noexcept;
  /* Steps all tasks in this target by `steps`. After stepping is done, report that `tid` has stopped. */
  void step_target(Tid tid, int steps) noexcept;
  /* Interrupts/stops all threads in this process space */
  void stop_all() noexcept;
  /* Query if we should interrupt the entire process and all it's tasks when we encounter a clone syscall */
  bool should_stop_on_clone() noexcept;
  /* Handle when a task exits or dies, so that we collect relevant meta data about it and also notifies the user
   * interface of the event */
  void reap_task(TaskInfo *task) noexcept;
  /** We've gotten a `TaskWaitResult` and we want to register it with the task it's associated with. This also
   * reads that task's registers and caches them.*/
  TaskInfo *register_task_waited(TaskWaitResult wait) noexcept;

  AddrPtr get_caching_pc(TaskInfo *t) noexcept;
  void set_pc(TaskInfo *t, TPtr<void> addr) noexcept;

  /** Set a task's virtual memory info, which for now involves the stack size for a task as well as it's stack
   * address. These are parameters known during the `clone` syscall and we will need them to be able to restore a
   * task, later on.*/
  void set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept;
  /* Cache the register contents of `tid`. */
  [[maybe_unused]] const user_regs_struct &cache_registers(Tid tid) noexcept;
  void synchronize_registers(Tid tid) noexcept;
  /* Set breakpoint att tracee `address`. If a breakpoint is already set there, we do nothing. We don't allow for
   * multiple breakpoints at the same location.*/
  void set_addr_breakpoint(TraceePointer<u64> address) noexcept;
  void set_fn_breakpoint(std::string_view function_name) noexcept;
  void set_source_breakpoints(std::string_view src, std::vector<SourceBreakpointDescriptor> &&descs) noexcept;
  void enable_breakpoint(Breakpoint &bp, bool setting) noexcept;
  void emit_stopped_at_breakpoint(LWP lwp, u32 bp_id) noexcept;
  void emit_stepped_stop(LWP lwp) noexcept;
  void emit_signal_event(LWP lwp, int signal) noexcept;
  // TODO(simon): major optimization can be done. We naively remove all breakpoints and then set
  //  what's in `addresses`. Why? because the stupid DAP doesn't do smart work and forces us to
  // to do it. But since we're not interested in solving this particular problem now, we'll do the stupid
  // thing
  void reset_addr_breakpoints(std::vector<TPtr<void>> addresses) noexcept;
  void reset_fn_breakpoints(std::vector<std::string_view> fn_names) noexcept;
  void reset_source_breakpoints(std::string_view source_filepath,
                                std::vector<SourceBreakpointDescriptor> &&bps) noexcept;

  bool kill() noexcept;
  bool terminate_gracefully() noexcept;
  bool detach() noexcept;
  AddrPtr task_rip(Tid tid) noexcept;
  void install_ptracestop_action(ptracestop::Action *action) noexcept;
  void restore_default_handler() noexcept;

  // todo(simon): These need re-factoring. They're only confusing as hell and misleading.
  void task_wait_emplace(int status, TaskWaitResult *wait) noexcept;
  void task_wait_emplace_stopped(int status, TaskWaitResult *wait) noexcept;
  void task_wait_emplace_signalled(int status, TaskWaitResult *wait) noexcept;
  void task_wait_emplace_exited(int status, TaskWaitResult *wait) noexcept;

  void process_exec(TaskInfo *t) noexcept;
  void process_clone(TaskInfo *t) noexcept;
  WE process_stopped(TaskInfo *t) noexcept;

  /* Check if we have any tasks left in the process space. */
  bool execution_not_ended() const noexcept;
  bool is_running() const noexcept;

  // Debug Symbols Related Logic
  void register_object_file(ObjectFile *obj) noexcept;

  // we pass TaskWaitResult here, because want to be able to ASSERT that we just exec'ed.
  // because we actually need to be at the *first* position on the stack, which, if we do at any other time we
  // might (very likely) not be.
  void read_auxv(TaskInfo &task);
  TargetSession session_type() const noexcept;
  std::string get_thread_name(Tid tid) const noexcept;
  utils::StaticVector<u8>::own_ptr read_to_vector(TraceePointer<void> addr, u64 bytes) noexcept;

  /** We do a lot of std::vector<T> foo; foo.reserve(threads.size()). This does just that. */
  template <typename T>
  constexpr std::vector<T>
  prepare_foreach_thread()
  {
    std::vector<T> vec;
    vec.reserve(threads.size());
    return vec;
  }

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
    auto EOF_REACHED = 0;
    while (total_read < sz) {
      auto read_bytes = pread64(mem_fd().get(), &result + total_read, sz - total_read, address.get());
      if (-1 == read_bytes) {
        PANIC(fmt::format("Failed to proc_fs read from {:p} because {}", (void *)address.get(), strerror(errno)));
      }
      if (0 == read_bytes)
        EOF_REACHED++;

      if (EOF_REACHED > 3)
        PANIC("Erred out because we attempted read beyond EOF multiple times.");
      total_read += read_bytes;
    }
    return result;
  }

  template <typename T>
  std::optional<T>
  read_type_safe(TPtr<T> addr)
  {
    typename TPtr<T>::Type result;
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    auto EOF_REACHED = 0;
    while (total_read < sz) {
      auto read_bytes = pread64(mem_fd().get(), &result + total_read, sz - total_read, addr.get());
      if (-1 == read_bytes) {
        return std::nullopt;
      }
      if (0 == read_bytes)
        EOF_REACHED++;

      if (EOF_REACHED > 3)
        return std::nullopt;
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

  void reaped_events() noexcept;
  void start_awaiter_thread() noexcept;
  sym::CallStack &build_callframe_stack(TaskInfo *task) noexcept;
  std::optional<SearchFnSymResult> find_fn_by_pc(TPtr<void> addr) const noexcept;
  std::optional<std::string_view> get_source(std::string_view name) noexcept;
  u8 *get_in_text_section(TPtr<void> address) const noexcept;
  ElfSection *get_text_section(AddrPtr addr) const noexcept;
  // Finds the first CompilationUnitFile that may contain `address` and returns the index of that file.
  std::optional<u64> cu_file_from_pc(TPtr<void> address) const noexcept;
  const std::vector<CompilationUnitFile> &cu_files() const noexcept;
  bool step_machine_active() const noexcept;
  void handle_execution_event(TaskInfo *task);

private:
  std::vector<CompilationUnitFile> m_files;
  std::optional<TPtr<void>> interpreter_base;
  std::optional<TPtr<void>> entry;
  std::unordered_map<Tid, user_regs_struct> register_cache;
  std::vector<sym::CallStack> frame_cache;
  AwaiterThread::handle awaiter_thread;
  TargetSession session;
  bool is_in_user_ptrace_stop;
  ptracestop::StopHandler *ptracestop_handler;
};