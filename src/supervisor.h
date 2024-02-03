#pragma once
#include "awaiter.h"
#include "breakpoint.h"
#include "common.h"
#include "events/event.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/types.h"
#include "lib/spinlock.h"
#include "ptrace.h"
#include "ptracestop_handlers.h"
#include "so_loading.h"
#include "symbolication/callstack.h"
#include "symbolication/elf.h"
#include "symbolication/fnsymbol.h"
#include "task.h"
#include <link.h>
#include <optional>
#include <thread>
#include <unordered_map>
#include <utils/scoped_fd.h>
#include <utils/static_vector.h>

namespace sym {
class Unwinder;
};

namespace ui {
struct UICommand;
namespace dap {
class VariablesReference;
};
}; // namespace ui

struct LWP
{
  Pid pid;
  Tid tid;

  constexpr bool operator<=>(const LWP &other) const = default;
};

using Address = std::uintptr_t;
struct ObjectFile;

class StopObserver;

struct TraceeController
{
  using handle = std::unique_ptr<TraceeController>;
  friend class Tracer;
  friend struct ui::UICommand;
  // Members
  pid_t task_leader;
  std::vector<ObjectFile *> object_files;
  ObjectFile *main_executable;
  utils::ScopedFd procfs_memfd;
  std::vector<TaskInfo> threads;
  std::unordered_map<pid_t, TaskVMInfo> task_vm_infos;
  BreakpointMap bps;
  TPtr<r_debug_extended> tracee_r_debug;
  SharedObjectMap shared_objects;
  bool waiting_for_all_stopped;
  StopObserver all_stopped_observer;

private:
  int next_var_ref = 0;
  std::unordered_map<int, ui::dap::VariablesReference> var_refs;
  // std::unordered_map<int, ui::dap::VarRef> vr;
  std::optional<TPtr<void>> interpreter_base;
  std::optional<TPtr<void>> entry;
  AwaiterThread::handle awaiter_thread;
  TargetSession session;
  ptracestop::StopHandler *ptracestop_handler;
  std::vector<std::unique_ptr<sym::Unwinder>> unwinders;
  // an unwinder that always returns sym::UnwindInfo* = nullptr
  sym::Unwinder *null_unwinder;
  bool ptrace_session_seized;

public:
  // Constructors
  TraceeController(pid_t process_space_id, utils::Notifier::WriteEnd awaiter_notify, TargetSession session,
                   bool seize_session, bool open_mem_fd = true) noexcept;
  TraceeController(const TraceeController &) = delete;
  TraceeController &operator=(const TraceeController &) = delete;

  /** Re-open proc fs mem fd. In cases where task has exec'd, for instance. */
  bool reopen_memfd() noexcept;
  /** Install breakpoints in the loader (ld.so). Used to determine what shared libraries tracee consists of. */
  void install_loader_breakpoints() noexcept;
  void on_so_event() noexcept;

  bool is_null_unwinder(sym::Unwinder *unwinder) const noexcept;

  // N.B(simon): process shared object's in parallell, determined by some heuristic (like for instance file size
  // could determine how much thread resources are subscribed to parsing a shared object.)
  void process_dwarf(std::vector<SharedObject::SoId> sos) noexcept;
  /** Return the open mem fd */
  utils::ScopedFd &mem_fd() noexcept;
  TaskInfo *get_task(pid_t pid) noexcept;
  /* wait on `task` or the entire target if `task` is nullptr */
  std::optional<TaskWaitResult> wait_pid(TaskInfo *task) noexcept;
  /* Create new task meta data for `tid` */
  void new_task(Tid tid, bool ui_update) noexcept;
  bool has_task(Tid tid) noexcept;
  /* Resumes all tasks in this target. */
  void resume_target(RunType type) noexcept;
  /* Resumes `task`, which can involve a process more involved than just calling ptrace. */
  void resume_task(TaskInfo &task, RunType type) noexcept;
  /* Interrupts/stops all threads in this process space */
  void stop_all(TaskInfo *requesting_task) noexcept;
  /* Handle when a task exits or dies, so that we collect relevant meta data about it and also notifies the user
   * interface of the event */
  void reap_task(TaskInfo &task) noexcept;
  /** We've gotten a `TaskWaitResult` and we want to register it with the task it's associated with. This also
   * reads that task's registers and caches them.*/
  TaskInfo *register_task_waited(TaskWaitResult wait) noexcept;

  AddrPtr get_caching_pc(TaskInfo &t) noexcept;
  void set_pc(TaskInfo &t, AddrPtr addr) noexcept;

  /** Set a task's virtual memory info, which for now involves the stack size for a task as well as it's stack
   * address. These are parameters known during the `clone` syscall and we will need them to be able to restore a
   * task, later on.*/
  void set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept;
  /* Set breakpoint att tracee `address`. If a breakpoint is already set there, we do nothing. We don't allow for
   * multiple breakpoints at the same location.*/
  void set_addr_breakpoint(TraceePointer<u64> address) noexcept;
  void set_fn_breakpoint(std::string_view function_name) noexcept;
  void set_source_breakpoints(std::string_view src, std::vector<SourceBreakpointDescriptor> &&descs) noexcept;
  bool set_tracer_bp(TPtr<u64> addr, BpType type) noexcept;
  Breakpoint *set_finish_fn_bp(TraceePointer<void> addr) noexcept;
  void enable_breakpoint(Breakpoint &bp, bool setting) noexcept;
  void emit_stopped_at_breakpoint(LWP lwp, u32 bp_id) noexcept;
  void emit_stepped_stop(LWP lwp) noexcept;
  void emit_stepped_stop(LWP lwp, std::string_view message, bool all_stopped) noexcept;
  void emit_signal_event(LWP lwp, int signal) noexcept;
  void emit_stopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool all_stopped,
                    std::vector<int> bps_hit) noexcept;

  // TODO(simon): major optimization can be done. We naively remove all breakpoints and then set
  //  what's in `addresses`. Why? because the stupid DAP doesn't do smart work and forces us to
  // to do it. But since we're not interested in solving this particular problem now, we'll do the stupid
  // thing
  void reset_addr_breakpoints(std::vector<AddrPtr> addresses) noexcept;
  void reset_fn_breakpoints(std::vector<std::string_view> fn_names) noexcept;
  void reset_source_breakpoints(std::string_view source_filepath,
                                std::vector<SourceBreakpointDescriptor> &&bps) noexcept;

  void remove_breakpoint(AddrPtr addr, BpType type) noexcept;

  bool kill() noexcept;
  bool terminate_gracefully() noexcept;
  bool detach() noexcept;

  template <typename StopAction, typename... Args>
  void
  install_thread_proceed(TaskInfo &t, Args... args) noexcept
  {
    DLOG("mdb", "[thread proceed]: install action {}", ptracestop::action_name<StopAction>());
    ptracestop_handler->set_and_run_action(t.tid, new StopAction{*this, t, args...});
  }

  void process_exec(TaskInfo &t) noexcept;
  Tid process_clone(TaskInfo &t) noexcept;

  /* Check if we have any tasks left in the process space. */
  bool execution_not_ended() const noexcept;
  bool is_running() const noexcept;

  // Debug Symbols Related Logic
  void register_object_file(ObjectFile *obj, bool is_main_executable, std::optional<AddrPtr> base_vma) noexcept;

  // we pass TaskWaitResult here, because want to be able to ASSERT that we just exec'ed.
  // because we actually need to be at the *first* position on the stack, which, if we do at any other time we
  // might (very likely) not be.
  void read_auxv(const TaskInfo &task);
  TargetSession session_type() const noexcept;
  std::string get_thread_name(Tid tid) const noexcept;
  std::vector<u8> read_to_vec(AddrPtr addr, u64 bytes) noexcept;
  utils::StaticVector<u8>::OwnPtr read_to_vector(AddrPtr addr, u64 bytes) noexcept;

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
  void
  write(TraceePointer<T> address, const T &value)
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

  std::optional<std::string> read_string(TraceePointer<char> address) noexcept;

  // Inform awaiter threads that event has been consumed & handled. "Wakes up" the awaiter thread.
  void reaped_events() noexcept;
  void start_awaiter_thread() noexcept;
  // Get the unwinder for `pc` - if no such unwinder exists, the "NullUnwinder" is returned, an unwinder that
  // always returns UnwindInfo* = `nullptr` results. This is to not have to do nullchecks against the Unwinder
  // itself.
  sym::Unwinder *get_unwinder_from_pc(AddrPtr pc) noexcept;
  sym::CallStack &build_callframe_stack(TaskInfo &task, CallStackRequest req) noexcept;
  std::vector<AddrPtr> &unwind_callstack(TaskInfo *task) noexcept;
  const std::vector<AddrPtr> &dwarf_unwind_callstack(TaskInfo *task, CallStackRequest req) noexcept;
  sym::Frame current_frame(NonNullPtr<TaskInfo> task) noexcept;
  sym::FunctionSymbol *find_fn_by_pc(AddrPtr addr, ObjectFile **foundIn) const noexcept;
  ObjectFile *find_obj_by_pc(AddrPtr addr) const noexcept;
  std::optional<std::string_view> get_source(std::string_view name) noexcept;
  // u8 *get_in_text_section(AddrPtr address) const noexcept;
  const ElfSection *get_text_section(AddrPtr addr) const noexcept;
  std::optional<ui::dap::VariablesReference> var_ref(int variables_reference) noexcept;

  std::array<ui::dap::Scope, 3> scopes_reference(int frame_id) noexcept;
  sym::Frame *frame(int frame_id) noexcept;
  void notify_all_stopped() noexcept;
  bool all_stopped() const noexcept;
  void set_pending_waitstatus(TaskWaitResult wait_result) noexcept;
  bool ptrace_was_seized() const noexcept;

  int new_frame_id(NonNullPtr<ObjectFile> owning_obj, TaskInfo &task) noexcept;
  int new_scope_id(NonNullPtr<ObjectFile> owning_obj, const sym::Frame *frame) noexcept;
  int new_var_id(int parent_id) noexcept;

private:
  void reset_variable_references() noexcept;
  int take_new_varref_id() noexcept;
  void reset_variable_ref_id() noexcept;
  // Writes breakpoint point and returns the original value found at that address
  u8 write_bp_byte(AddrPtr addr) noexcept;
};