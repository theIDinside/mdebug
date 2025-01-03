#pragma once
#include "awaiter.h"
#include "bp.h"
#include "common.h"
#include "event_queue.h"
#include "events/event.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/types.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include <mdbsys/ptrace.h>
#include "ptracestop_handlers.h"
#include "so_loading.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/elf.h"
#include "symbolication/fnsymbol.h"
#include "task.h"
#include "utils/byte_buffer.h"
#include "utils/expected.h"
#include <optional>
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
class ObjectFile;
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

// Controller for one process
class TraceeController
{
  friend class Tracer;
  friend struct ui::UICommand;
  // The process pid, or the initial task that was spawned for this process
  pid_t mTaskLeader;
  // The symbol files that this process is "built of"
  std::vector<std::shared_ptr<SymbolFile>> mSymbolFiles;
  // The main executable symbol file; the initial executable binary, i.e. the one passed to `execve` at some point.
  std::shared_ptr<SymbolFile> mMainExecutable;
  // The tasks that exist in this "process space"
  std::vector<std::shared_ptr<TaskInfo>> mThreads;
  // Tasks that have exited.
  std::vector<std::shared_ptr<TaskInfo>> mExitedThreads;
  // More low level information about tasks's. The idea (maybe?) is that at some point we will be able
  // to restore a process space, by doing some manual cloning of tasks, making checkpoint-like debugging possible
  // note: not as powerful as rr, in any sense of the word, but may be neat.
  std::unordered_map<pid_t, TaskVMInfo> mThreadInfos;
  // The breakpoints set by the user
  UserBreakpoints mUserBreakpoints;
  // The shared objects / dynamic libraries used by this process
  SharedObjectMap mSharedObjects;
  // Stopping of all tasks requested by some event in the event loop. This flag is cleared, once all tasks have
  // been stopped.
  bool mStopAllTasksRequested;
  // Emits "all stopped" event to all subscribers
  Publisher<void> mAllStopPublisher{};
  // Emits "new module/new dynamic library" event to all subscribers
  Publisher<SymbolFile *> mNewObjectFilePublisher{};
  // Interface type native|remote
  InterfaceType mInterfaceType;
  // The Debug Adapter Protocol client, by which we communicate with. It handles the communication with the
  // Debug Adapter implementation.
  // TODO: at some point it should be configurable, to use other channels than just stdio. Should be fairly
  // trivial.
  ui::dap::DebugAdapterClient *mDebugAdapterClient{nullptr};

  // Monotonically increasing "variable reference" as defined by the debug adapter protocol.
  int mNextVariableReference = 0;
  // The base address that defines the interpreter that we use. It gives us the system path to where we can load
  // and parse debug symbol information from the system linker, so that we can install breakpoints in specific
  // places when the linker loads libraries. This is how we track what dynamic libraries is being used by a process
  // P
  std::optional<TPtr<void>> mInterpreterBase;
  // The entry point of an executable (usually the first instruction of the function `_start` for c-run time/posix
  // applications on Linux)
  std::optional<TPtr<void>> mEntry;
  // Is Attach/Launch session?
  TargetSession mSessionKind;
  // The currently installed Stop handler
  ptracestop::StopHandler *mStopHandler;
  // an unwinder that always returns sym::UnwindInfo* = nullptr
  sym::Unwinder *mNullUnwinder;
  // The command interface that controls execution of the target. If the target is a "native" one, it means we're
  // probably using ptrace if it's a remote one, it's probably a remote process on another system, or on this
  // system, where it's something like gdbserver controlling the tracee/debuggee and we commmunicate with that
  // instead. This is how rr works for instance, gdb sends GdbServer commands to it.
  std::unique_ptr<tc::TraceeCommandInterface> mTraceeInterface;
  // The auxilliary vector of the application/process being debugged. Contains things like entry, interpreter base,
  // what the executable file was etc.
  tc::Auxv mAuxiliaryVector{};
  // Whether this is the very first stop wait status we have seen
  bool mOnEntry{false};

  // Whether or not a process exit has been seen for this process.
  bool mIsExited{false};

  // FORK constructor
  TraceeController(TraceeController &parent, tc::Interface &&interface) noexcept;
  // Constructors
  TraceeController(TargetSession session, tc::Interface &&interface, InterfaceType type) noexcept;

public:
  static std::unique_ptr<TraceeController> create(TargetSession session, tc::Interface &&interface,
                                                  InterfaceType type);
  ~TraceeController() noexcept;

  TraceeController(const TraceeController &) = delete;
  TraceeController &operator=(const TraceeController &) = delete;

  void TearDown(bool killProcess) noexcept;
  bool IsExited() const noexcept;
  void ConfigureDapClient(ui::dap::DebugAdapterClient *client) noexcept;
  // Called when a ("this") process forks
  std::unique_ptr<TraceeController> Fork(tc::Interface &&interface) noexcept;

  // Look up if the debugger has parsed symbol object file with `path` and return it. Otherwise returns nullptr
  std::shared_ptr<SymbolFile> LookupSymbolFile(const Path &path) noexcept;
  // Return the entry address (usually address of _start) for this executable
  AddrPtr EntryAddress() const noexcept;
  /** Install breakpoints in the loader (ld.so). Used to determine what shared libraries tracee consists of. */
  TPtr<r_debug_extended> InstallDynamicLoaderBreakpoints() noexcept;
  // Called when a new dynamic library has been loaded into the process vm space
  void OnSharedObjectEvent() noexcept;
  // Check if new breakpoint locations need to be installed, because of a new symbol file being loaded.
  bool CheckBreakpointLocationsForSymbolFile(SymbolFile &symbolFile, UserBreakpoint &userBreakpoint,
                                             std::vector<std::shared_ptr<BreakpointLocation>> &locs) noexcept;
  // Check if new breakpoint locations need to be installed, because of a new symbol file being loaded.
  void DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>> &&newSymbolFiles) noexcept;

  bool IsNullUnwinder(sym::Unwinder *unwinder) const noexcept;

  // signals if threads are independently resumable. so if user does continue { thread: 2 }, it only resumes that
  // thread also; it also means when for instance { thread: 9 } hits a breakpoint, all threads are stopped in their
  // track.
  bool IsIndividualTaskControlConfigured() noexcept;
  std::span<std::shared_ptr<TaskInfo>> GetThreads() noexcept;
  std::span<std::shared_ptr<TaskInfo>> GetExitedThreads() noexcept;
  void AddTask(std::shared_ptr<TaskInfo> &&task) noexcept;
  u32 RemoveTaskIf(std::function<bool(const std::shared_ptr<TaskInfo> &)> &&predicate);
  Tid TaskLeaderTid() const noexcept;
  TaskInfo *GetTaskByTid(pid_t pid) noexcept;
  UserBreakpoints &GetUserBreakpoints() noexcept;
  /* Create new task meta data for `tid` */
  void CreateNewTask(Tid tid, bool running) noexcept;
  bool HasTask(Tid tid) noexcept;
  /* Resumes all tasks in this target. */
  void ResumeTask(tc::RunType type) noexcept;
  /* Resumes `task`, which can involve a process more involved than just calling ptrace. */
  void ResumeTask(TaskInfo &task, tc::ResumeAction type) noexcept;
  /* Interrupts/stops all threads in this process space */
  void StopAllTasks(TaskInfo *requestingTask) noexcept;
  /** We've gotten a `TaskWaitResult` and we want to register it with the task it's associated with. This also
   * reads that task's registers and caches them.*/
  TaskInfo *RegisterTaskWaited(TaskWaitResult wait) noexcept;

  // Cache the register contents for `task` and return the program counter.
  AddrPtr CacheAndGetPcFor(TaskInfo &task) noexcept;
  // Set the cached value for the program counter for `task`, but also write it into memory so that the task pc in
  // the tracee actually reflects this value
  void SetProgramCounterFor(TaskInfo &task, AddrPtr addr) noexcept;

  /** Set a task's virtual memory info, which for now involves the stack size for a task as well as it's stack
   * address. These are parameters known during the `clone` syscall and we will need them to be able to restore a
   * task, later on.*/
  void SetTaskVmInfo(Tid tid, TaskVMInfo vm_info) noexcept;

  void SetIsOnEntry(bool setting) noexcept;
  bool IsOnEntry() const noexcept;

  // Emit event FOO at stop
  void EmitStoppedAtBreakpoints(LWP lwp, u32 bp_id, bool all_stopped) noexcept;
  void EmitSteppedStop(LWP lwp) noexcept;
  void EmitSteppedStop(LWP lwp, std::string_view message, bool all_stopped) noexcept;
  void EmitSignalEvent(LWP lwp, int signal) noexcept;
  void EmitStopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool all_stopped,
                   std::vector<int> bps_hit) noexcept;
  void EmitBreakpointEvent(std::string_view reason, const UserBreakpoint &bp,
                           std::optional<std::string> message) noexcept;
  tc::ProcessedStopEvent ProcessDeferredStopEvent(TaskInfo &t, DeferToSupervisor &evt) noexcept;

  // Get (&& ||) Create breakpoint locations
  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
  GetOrCreateBreakpointLocation(AddrPtr addr) noexcept;
  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
  GetOrCreateBreakpointLocation(AddrPtr addr, sym::dw::SourceCodeFile &sourceCodeFile, const sym::dw::LineTableEntry& lte) noexcept;

  utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
  GetOrCreateBreakpointLocationWithSourceLoc(AddrPtr addr,
                                             std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept;
  void SetSourceBreakpoints(const std::filesystem::path &source_filepath,
                            const Set<SourceBreakpointSpec> &bps) noexcept;
  void UpdateSourceBreakpoints(const std::filesystem::path &source_filepath,
                               std::vector<SourceBreakpointSpec> &&add,
                               const std::vector<SourceBreakpointSpec> &remove) noexcept;

  void SetInstructionBreakpoints(const Set<InstructionBreakpointSpec> &bps) noexcept;
  void SetFunctionBreakpoints(const Set<FunctionBreakpointSpec> &bps) noexcept;
  void RemoveBreakpoint(u32 bp_id) noexcept;

  // Right now, I don't think we care or empathize at all with anything - we just abort/panic, more or less.
  bool TryTerminateGracefully() noexcept;
  bool Detach(bool resume) noexcept;

  void SetAndCallRunAction(Tid tid, ptracestop::ThreadProceedAction *action) noexcept;

  template <typename StopAction, typename... Args>
  void
  InstallStopActionHandler(TaskInfo &t, Args... args) noexcept
  {
    DBGLOG(core, "[thread proceed]: install action {}", ptracestop::action_name<StopAction>());
    mStopHandler->set_and_run_action(t.tid, new StopAction{*this, t, args...});
  }

  void PostExec(const std::string &exe) noexcept;

  /* Check if we have any tasks left in the process space. */
  bool ExecutionHasNotEnded() const noexcept;
  bool IsRunning() const noexcept;

  // Debug Symbols Related Logic
  void RegisterObjectFile(TraceeController *tc, std::shared_ptr<ObjectFile> &&obj, bool isMainExecutable,
                          AddrPtr relocatedBase) noexcept;

  void RegisterSymbolFile(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept;

  // we pass TaskWaitResult here, because want to be able to ASSERT that we just exec'ed.
  // because we actually need to be at the *first* position on the stack, which, if we do at any other time we
  // might (very likely) not be.
  void ReadAuxiliaryVector(TaskInfo &task);
  void ParseAuxiliaryVectorInfo(tc::Auxv &&aux) noexcept;

  TargetSession GetSessionType() const noexcept;

  utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead> SafeRead(AddrPtr addr, u64 bytes) noexcept;
  utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead> SafeRead(std::pmr::memory_resource *allocator,
                                                                            AddrPtr addr, u64 bytes) noexcept;
  utils::StaticVector<u8>::OwnPtr ReadToVector(AddrPtr addr, u64 bytes) noexcept;

  template <typename T>
  T
  ReadType(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type result;
    u8 *ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    while (total_read < sz) {
      const auto read_address = address.as_void() += total_read;
      const auto read_result = mTraceeInterface->ReadBytes(read_address, sz - total_read, ptr + total_read);
      if (!read_result.success()) {
        PANIC(fmt::format("Failed to proc_fs read from {:p} because {}", (void *)address.get(), strerror(errno)));
      }
      total_read += read_result.bytes_read;
    }
    return result;
  }

  template <typename T>
  std::optional<T>
  SafeReadType(TPtr<T> addr)
  {
    typename TPtr<T>::Type result;
    auto ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    while (total_read < sz) {
      const auto read_address = addr.as_void() += total_read;
      const auto read_result = mTraceeInterface->ReadBytes(read_address, sz - total_read, ptr + total_read);
      if (!read_result.success()) {
        return std::nullopt;
      }
      total_read += read_result.bytes_read;
    }
    return result;
  }

  template <typename T>
  void
  Write(TraceePointer<T> address, const T &value)
  {
    auto write_res = mTraceeInterface->Write(address, value);
    if (!write_res.is_expected()) {
      PANIC(fmt::format("Failed to proc_fs write to {:p}", (void *)address.get()));
    }
  }

  // Read (null-terminated) string starting at `address` in tracee VM space
  std::optional<std::string> ReadString(TraceePointer<char> address) noexcept;
  // Get the unwinder for `pc` - if no such unwinder exists, the "NullUnwinder" is returned, an unwinder that
  // always returns UnwindInfo* = `nullptr` results. This is to not have to do nullchecks against the Unwinder
  // itself.
  sym::UnwinderSymbolFilePair GetUnwinderUsingPc(AddrPtr pc) noexcept;
  sym::CallStack &BuildCallFrameStack(TaskInfo &task, CallStackRequest req) noexcept;

  // Get "bottom most" frame
  sym::Frame GetCurrentFrame(TaskInfo &task) noexcept;
  std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>> FindFunctionByPc(AddrPtr addr) noexcept;
  SymbolFile *FindObjectByPc(AddrPtr addr) noexcept;

  Publisher<void> &GetPublisher(ObserverType type) noexcept;
  void EmitAllStopped() noexcept;
  bool IsAllStopped() const noexcept;
  bool IsSessionAllStopMode() const noexcept;
  TaskInfo *SetPendingWaitstatus(TaskWaitResult wait_result) noexcept;

  void CacheRegistersFor(TaskInfo &t) noexcept;
  tc::TraceeCommandInterface &GetInterface() noexcept;

  // Core event handlers
  tc::ProcessedStopEvent HandleThreadCreated(TaskInfo *task, const ThreadCreated &evt,
                                             const RegisterData &register_data) noexcept;
  tc::ProcessedStopEvent HandleThreadExited(TaskInfo *task, const ThreadExited &evt) noexcept;
  tc::ProcessedStopEvent HandleProcessExit(const ProcessExited &evt) noexcept;
  tc::ProcessedStopEvent HandleFork(const ForkEvent &evt) noexcept;
  tc::ProcessedStopEvent HandleClone(const Clone& evt) noexcept;

  ui::dap::DebugAdapterClient *GetDebugAdapterProtocolClient() const noexcept;

private:
  // Writes breakpoint point and returns the original value found at that address
  utils::Expected<u8, BpErr> InstallSoftwareBreakpointLocation(AddrPtr addr) noexcept;
};

struct ProbeInfo
{
  AddrPtr address;
  std::string name;
};

std::vector<ProbeInfo> parse_stapsdt_note(const Elf *elf, const ElfSection *section) noexcept;