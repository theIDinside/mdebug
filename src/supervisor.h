#pragma once
#include "awaiter.h"
#include "bp.h"
#include "common.h"
#include "event_queue.h"
#include "events/event.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/types.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "lib/spinlock.h"
#include "ptrace.h"
#include "ptracestop_handlers.h"
#include "so_loading.h"
#include "symbolication/callstack.h"
#include "symbolication/elf.h"
#include "symbolication/fnsymbol.h"
#include "task.h"
#include "utils/byte_buffer.h"
#include "utils/expected.h"
#include <optional>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utils/scoped_fd.h>
#include <utils/static_vector.h>

template <typename T> using Set = std::unordered_set<T>;

struct DeferToSupervisor;

namespace sym {
class Unwinder;
struct UnwinderSymbolFilePair;
}; // namespace sym

namespace ui {
struct UICommand;
namespace dap {
class VariablesReference;
class DebugAdapterClient;
}; // namespace dap
}; // namespace ui

using Address = std::uintptr_t;
struct ObjectFile;
class SymbolFile;

class StopObserver;

struct NonFullRead
{
  std::unique_ptr<utils::ByteBuffer> bytes;
  u32 unread_bytes;
  int err_no;
};

/// Creates a `SymbolFile` using either an existing `ObjectFile` as storage or constructing a new one.
/// When debugging 2 processes with the same binaries, we don't want duplicate storage.
auto createSymbolFile(auto &tc, auto path, AddrPtr addr) noexcept -> std::shared_ptr<SymbolFile>;

enum class InterfaceType
{
  Ptrace,
  GdbRemote
};

enum class ObserverType
{
  AllStop
};

class TraceeController
{
  using handle = std::unique_ptr<TraceeController>;
  friend class Tracer;
  friend struct ui::UICommand;
  // Members
  pid_t task_leader;
  std::vector<std::shared_ptr<SymbolFile>> symbol_files;
  std::shared_ptr<SymbolFile> main_executable;
  std::vector<std::shared_ptr<TaskInfo>> threads;
  std::unordered_map<pid_t, TaskVMInfo> task_vm_infos;
  UserBreakpoints pbps;
  SharedObjectMap shared_objects;
  bool stop_all_requested;
  Publisher<void> all_stop{};
  Publisher<SymbolFile *> new_objectfile{};
  TPtr<r_debug_extended> tracee_r_debug{nullptr};
  InterfaceType interface_type;
  ui::dap::DebugAdapterClient *dap_client{nullptr};
  std::optional<Pid> parent{};

  int next_var_ref = 0;
  std::optional<TPtr<void>> interpreter_base;
  std::optional<TPtr<void>> entry;
  TargetSession session;
  ptracestop::StopHandler *stop_handler;
  // an unwinder that always returns sym::UnwindInfo* = nullptr
  sym::Unwinder *null_unwinder;
  std::unique_ptr<tc::TraceeCommandInterface> tracee_interface;
  tc::Auxv auxiliary_vector{};
  bool on_entry{false};
  bool reaped{false};

  // FORK constructor
  TraceeController(TraceeController &parent, tc::Interface &&interface) noexcept;
  // Constructors
  TraceeController(TargetSession session, tc::Interface &&interface, InterfaceType type) noexcept;

public:

  static std::unique_ptr<TraceeController> create(TargetSession session, tc::Interface &&interface, InterfaceType type);
  ~TraceeController() noexcept;

  TraceeController(const TraceeController &) = delete;
  TraceeController &operator=(const TraceeController &) = delete;

  void configure_dap_client(ui::dap::DebugAdapterClient *client) noexcept;
  std::unique_ptr<TraceeController> fork(tc::Interface &&interface) noexcept;

  std::shared_ptr<SymbolFile> lookup_symbol_file(const Path &path) noexcept;

  /** Install breakpoints in the loader (ld.so). Used to determine what shared libraries tracee consists of. */
  TPtr<r_debug_extended> install_loader_breakpoints() noexcept;
  void on_so_event() noexcept;
  std::optional<std::shared_ptr<BreakpointLocation>> reassess_bploc_for_symfile(SymbolFile &symbol_file,
                                                                                UserBreakpoint &user_bp) noexcept;
  void do_breakpoints_update(std::vector<std::shared_ptr<SymbolFile>> &&new_symbol_files) noexcept;

  bool is_null_unwinder(sym::Unwinder *unwinder) const noexcept;

  // signals if threads are independently resumable. so if user does continue { thread: 2 }, it only resumes that
  // thread also; it also means when for instance { thread: 9 } hits a breakpoint, all threads are stopped in their
  // track.
  bool independent_task_resume_control() noexcept;

  // N.B(simon): process shared object's in parallell, determined by some heuristic (like for instance file size
  // could determine how much thread resources are subscribed to parsing a shared object.)
  void process_dwarf(std::vector<SharedObject::SoId> sos) noexcept;

  std::span<std::shared_ptr<TaskInfo>> get_threads() noexcept;
  void AddTask(std::shared_ptr<TaskInfo>&& task) noexcept;
  u32 RemoveTaskIf(std::function<bool(const std::shared_ptr<TaskInfo>&)>&& predicate);

  Tid get_task_leader() const noexcept;
  TaskInfo *get_task(pid_t pid) noexcept;
  UserBreakpoints& user_breakpoints() noexcept;
  /* wait on `task` or the entire target if `task` is nullptr */
  std::optional<TaskWaitResult> wait_pid(TaskInfo *task) noexcept;
  /* Create new task meta data for `tid` */
  void new_task(Tid tid, bool running) noexcept;
  bool has_task(Tid tid) noexcept;
  /* Resumes all tasks in this target. */
  void resume_target(tc::RunType type) noexcept;
  /* Resumes `task`, which can involve a process more involved than just calling ptrace. */
  void resume_task(TaskInfo &task, tc::ResumeAction type) noexcept;
  /* Interrupts/stops all threads in this process space */
  void stop_all(TaskInfo *requesting_task) noexcept;
  /** We've gotten a `TaskWaitResult` and we want to register it with the task it's associated with. This also
   * reads that task's registers and caches them.*/
  TaskInfo *register_task_waited(TaskWaitResult wait) noexcept;

  AddrPtr get_caching_pc(TaskInfo &t) noexcept;
  void set_pc(TaskInfo &t, AddrPtr addr) noexcept;

  /** Set a task's virtual memory info, which for now involves the stack size for a task as well as it's stack
   * address. These are parameters known during the `clone` syscall and we will need them to be able to restore a
   * task, later on.*/
  void set_task_vm_info(Tid tid, TaskVMInfo vm_info) noexcept;

  void set_on_entry(bool setting) noexcept;
  bool is_on_entry() const noexcept;

  void emit_stopped_at_breakpoint(LWP lwp, u32 bp_id, bool all_stopped) noexcept;
  void emit_stepped_stop(LWP lwp) noexcept;
  void emit_stepped_stop(LWP lwp, std::string_view message, bool all_stopped) noexcept;
  void emit_signal_event(LWP lwp, int signal) noexcept;
  void emit_stopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool all_stopped,
                    std::vector<int> bps_hit) noexcept;
  void emit_breakpoint_event(std::string_view reason, const UserBreakpoint &bp,
                             std::optional<std::string> message) noexcept;
  tc::ProcessedStopEvent process_deferred_stopevent(TaskInfo &t, DeferToSupervisor &evt) noexcept;

  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
  get_or_create_bp_location(AddrPtr addr, bool attempt_src_resolve) noexcept;
  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
  get_or_create_bp_location(AddrPtr addr, AddrPtr base, sym::dw::SourceCodeFile &src_code_file) noexcept;

  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
  get_or_create_bp_location(AddrPtr addr, std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept;
  void set_source_breakpoints(const std::filesystem::path &source_filepath,
                              const Set<SourceBreakpointSpec> &bps) noexcept;
  void update_source_bps(const std::filesystem::path &source_filepath, std::vector<SourceBreakpointSpec> &&add,
                         const std::vector<SourceBreakpointSpec> &remove) noexcept;

  void set_instruction_breakpoints(const Set<InstructionBreakpointSpec> &bps) noexcept;
  void set_fn_breakpoints(const Set<FunctionBreakpointSpec> &bps) noexcept;

  void remove_breakpoint(u32 bp_id) noexcept;

  bool terminate_gracefully() noexcept;
  bool detach(bool resume) noexcept;

  void set_and_run_action(Tid tid, ptracestop::ThreadProceedAction *action) noexcept;

  template <typename StopAction, typename... Args>
  void
  install_thread_proceed(TaskInfo &t, Args... args) noexcept
  {
    DBGLOG(core, "[thread proceed]: install action {}", ptracestop::action_name<StopAction>());
    stop_handler->set_and_run_action(t.tid, new StopAction{*this, t, args...});
  }

  void post_exec(const std::string &exe) noexcept;

  /* Check if we have any tasks left in the process space. */
  bool execution_not_ended() const noexcept;
  bool is_running() const noexcept;

  // Debug Symbols Related Logic
  void register_object_file(TraceeController *tc, std::shared_ptr<ObjectFile> obj, bool is_main_executable,
                            AddrPtr relocated_base) noexcept;

  void register_symbol_file(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept;

  // we pass TaskWaitResult here, because want to be able to ASSERT that we just exec'ed.
  // because we actually need to be at the *first* position on the stack, which, if we do at any other time we
  // might (very likely) not be.
  void read_auxv(TaskInfo &task);
  void read_auxv_info(tc::Auxv &&aux) noexcept;

  TargetSession session_type() const noexcept;

  utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead> safe_read(AddrPtr addr, u64 bytes) noexcept;
  utils::StaticVector<u8>::OwnPtr read_to_vector(AddrPtr addr, u64 bytes) noexcept;

  template <typename T>
  T
  read_type(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type result;
    u8 *ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    while (total_read < sz) {
      const auto read_address = address.as_void() += total_read;
      const auto read_result = tracee_interface->read_bytes(read_address, sz - total_read, ptr + total_read);
      if (!read_result.success()) {
        PANIC(fmt::format("Failed to proc_fs read from {:p} because {}", (void *)address.get(), strerror(errno)));
      }
      total_read += read_result.bytes_read;
    }
    return result;
  }

  template <typename T>
  std::optional<T>
  read_type_safe(TPtr<T> addr)
  {
    typename TPtr<T>::Type result;
    auto ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    while (total_read < sz) {
      const auto read_address = addr.as_void() += total_read;
      const auto read_result = tracee_interface->read_bytes(read_address, sz - total_read, ptr + total_read);
      if (!read_result.success()) {
        return std::nullopt;
      }
      total_read += read_result.bytes_read;
    }
    return result;
  }

  template <typename T>
  void
  write(TraceePointer<T> address, const T &value)
  {
    auto write_res = tracee_interface->write(address, value);
    if (!write_res.is_expected()) {
      PANIC(fmt::format("Failed to proc_fs write to {:p}", (void *)address.get()));
    }
  }

  std::optional<std::string> read_string(TraceePointer<char> address) noexcept;
  // Get the unwinder for `pc` - if no such unwinder exists, the "NullUnwinder" is returned, an unwinder that
  // always returns UnwindInfo* = `nullptr` results. This is to not have to do nullchecks against the Unwinder
  // itself.
  sym::UnwinderSymbolFilePair get_unwinder_from_pc(AddrPtr pc) noexcept;
  sym::CallStack &build_callframe_stack(TaskInfo &task, CallStackRequest req) noexcept;

  sym::Frame current_frame(TaskInfo &task) noexcept;
  std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>> find_fn_by_pc(AddrPtr addr) noexcept;
  SymbolFile *find_obj_by_pc(AddrPtr addr) noexcept;

  // u8 *get_in_text_section(AddrPtr address) const noexcept;
  const ElfSection *get_text_section(AddrPtr addr) noexcept;
  std::optional<ui::dap::VariablesReference> var_ref(int variables_reference) noexcept;

  Publisher<void>& observer(ObserverType type) noexcept;
  void notify_all_stopped() noexcept;
  bool all_stopped() const noexcept;
  bool session_all_stop_mode() const noexcept;
  TaskInfo *set_pending_waitstatus(TaskWaitResult wait_result) noexcept;

  void cache_registers(TaskInfo &t) noexcept;
  tc::TraceeCommandInterface &get_interface() noexcept;
  std::optional<AddrPtr> get_interpreter_base() const noexcept;
  std::shared_ptr<SymbolFile> get_main_executable() const noexcept;

  tc::ProcessedStopEvent handle_thread_created(TaskInfo *task, const ThreadCreated &evt,
                                               const RegisterData &register_data) noexcept;
  tc::ProcessedStopEvent handle_thread_exited(TaskInfo *task, const ThreadExited &evt) noexcept;
  tc::ProcessedStopEvent handle_process_exit(const ProcessExited &evt) noexcept;
  tc::ProcessedStopEvent handle_fork(const Fork &evt) noexcept;

  ui::dap::DebugAdapterClient* get_dap_client() const noexcept;

private:
  // Writes breakpoint point and returns the original value found at that address
  utils::Expected<u8, BpErr> install_software_bp_loc(AddrPtr addr) noexcept;
};

struct ProbeInfo
{
  AddrPtr address;
  std::string name;
};

std::vector<ProbeInfo> parse_stapsdt_note(const Elf *elf, const ElfSection *section) noexcept;