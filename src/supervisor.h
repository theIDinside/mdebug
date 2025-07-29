/** LICENSE TEMPLATE */
#pragma once
#include "bp.h"
#include "common.h"
#include "event_queue.h"
#include "events/event.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/types.h"
#include "interface/remotegdb/connection.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/elf.h"
#include "symbolication/fnsymbol.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "task_scheduling.h"
#include "utils/expected.h"
#include <mdbsys/ptrace.h>
#include <memory_resource>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utils/leak_vector.h>
#include <utils/scoped_fd.h>

namespace mdb {
template <typename T> using Set = std::unordered_set<T>;
struct DeferToSupervisor;
class ByteBuffer;

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
  std::unique_ptr<ByteBuffer> mBytes;
  u32 mUnreadBytes;
  int mErrorNumber;
};

/// Creates a `SymbolFile` using either an existing `ObjectFile` as storage or constructing a new one.
/// When debugging 2 processes with the same binaries, we don't want duplicate storage.
auto createSymbolFile(auto &tc, auto path, AddrPtr addr) noexcept -> std::shared_ptr<SymbolFile>;

enum class InterfaceType
{
  Ptrace,
  GdbRemote,
};

enum class ObserverType
{
  AllStop
};

enum class SupervisorEventHandlerAction
{
  Default,
  Defer
};

// Controller for one process
class TraceeController
{
  friend class Tracer;
  friend struct ui::UICommand;
  // The id given to this process by the debugger
  u32 mSessionId;
  // This process' parent pid
  pid_t mParentPid;
  // The process pid, or the initial task that was spawned for this process
  pid_t mTaskLeader;
  // The symbol files that this process is "built of"
  std::vector<std::shared_ptr<SymbolFile>> mSymbolFiles;
  // The main executable symbol file; the initial executable binary, i.e. the one passed to `execve` at some point.
  std::shared_ptr<SymbolFile> mMainExecutable;
  // The tasks that exist in this "process space". Since tasks often are looked up by tid, before we want to do
  // something with it we save an indirection by storing the tid inline here, same goes for mExitedThreads.
  std::vector<TaskInfo::TaskInfoEntry> mThreads;
  // Tasks that have exited.
  std::vector<TaskInfo::TaskInfoEntry> mExitedThreads;
  // More low level information about tasks's. The idea (maybe?) is that at some point we will be able
  // to restore a process space, by doing some manual cloning of tasks, making checkpoint-like debugging possible
  // note: not as powerful as rr, in any sense of the word, but may be neat.
  std::unordered_map<pid_t, TaskVMInfo> mThreadInfos;
  // The breakpoints set by the user
  UserBreakpoints mUserBreakpoints;
  // Emits "all stopped" event to all subscribers
  Publisher<void> mAllStopPublisher{};
  // Emits "new module/new dynamic library" event to all subscribers
  Publisher<SymbolFile *> mNewObjectFilePublisher{};

  Publisher<void> mOnExecOrExitPublisher{};

  // Interface type native|remote
  InterfaceType mInterfaceType;
  // The Debug Adapter Protocol client, by which we communicate with. It handles the communication with the
  // Debug Adapter implementation.
  // TODO: at some point it should be configurable, to use other channels than just stdio. Should be fairly
  // trivial.
  ui::dap::DebugAdapterClient *mDebugAdapterClient{nullptr};

  // Monotonically increasing "variable reference" as defined by the debug adapter protocol.
  int mNextVariableReference = 0;

  // Is Attach/Launch session?
  TargetSession mSessionKind;
  // The currently installed Stop handler
  std::unique_ptr<TaskScheduler> mScheduler;
  // an unwinder that always returns sym::UnwindInfo* = nullptr
  sym::Unwinder *mNullUnwinder;
  // The command interface that controls execution of the target. If the target is a "native" one, it means we're
  // probably using ptrace if it's a remote one, it's probably a remote process on another system, or on this
  // system, where it's something like gdbserver controlling the tracee/debuggee and we commmunicate with that
  // instead. This is how rr works for instance, gdb sends GdbServer commands to it.
  std::unique_ptr<tc::TraceeCommandInterface> mTraceeInterface;

  // The auxilliary vector of the application/process being debugged. Contains things like entry, interpreter base,
  // what the executable file was etc:

  // The base address that defines the interpreter that we use. It gives us the system path to where we can load
  // and parse debug symbol information from the system linker, so that we can install breakpoints in specific
  // places when the linker loads libraries. This is how we track what dynamic libraries is being used by a process

  // The entry point of an executable (usually the first instruction of the function `_start` for c-run time/posix
  // applications on Linux)
  ParsedAuxiliaryVector mParsedAuxiliaryVector;

  bool mConfigurationIsDone : 1 {false};
  // Whether this is the very first stop wait status we have seen
  bool mOnEntry : 1 {false};
  // Whether or not a process exit has been seen for this process.
  bool mIsExited : 1 {false};
  // If this process was vforked it needs special attention/massaging until it performs an EXEC. It can't do the
  // normal fork/clone/exec dances, as this would affect the caller of vfork's process space as well. This flag is
  // set by the comment-labled FORK constructor of TraceeController.
  bool mIsVForking : 1 {false};
  // Signals whether any stop that is encounted should signal to the debug adapter that everything stopped at the
  // same time.
  bool mAllStopSession : 1 {false};

  int mCreationEventTime{0};
  int mCurrentEventTime{0};

  BreakpointBehavior mBreakpointBehavior{BreakpointBehavior::StopAllThreadsWhenHit};

  // FORK constructor
  TraceeController(u32 sessionId, TraceeController &parent, tc::Interface &&interface, bool isVFork) noexcept;
  // Constructors
  TraceeController(u32 sessionId, TargetSession session, tc::Interface &&interface, InterfaceType type) noexcept;

public:
  static std::unique_ptr<TraceeController> create(u32 sessionId, TargetSession session, tc::Interface &&interface,
                                                  InterfaceType type);
  ~TraceeController() noexcept;

  TraceeController(const TraceeController &) = delete;
  TraceeController &operator=(const TraceeController &) = delete;

  void ConfigureBreakpointBehavior(BreakpointBehavior behavior) noexcept;
  constexpr BreakpointBehavior
  GetBreakpointBehavior() const noexcept
  {
    return mBreakpointBehavior;
  }
  void TearDown(bool killProcess) noexcept;
  bool IsExited() const noexcept;
  void ConfigureDapClient(ui::dap::DebugAdapterClient *client) noexcept;
  void Disconnect() noexcept;
  void
  ConfigurationDone() noexcept
  {
    mConfigurationIsDone = true;
  }
  // Called when a ("this") process forks
  std::unique_ptr<TraceeController> Fork(tc::Interface &&interface, bool isVFork) noexcept;

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
                                             std::vector<Ref<BreakpointLocation>> &locs) noexcept;
  // Check if new breakpoint locations need to be installed, because of a new symbol file being loaded.
  void DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>> &&newSymbolFiles) noexcept;

  bool IsNullUnwinder(sym::Unwinder *unwinder) const noexcept;

  // signals if threads are independently resumable. so if user does continue { thread: 2 }, it only resumes that
  // thread also; it also means when for instance { thread: 9 } hits a breakpoint, all threads are stopped in their
  // track.
  bool IsIndividualTaskControlConfigured() noexcept;
  std::span<TaskInfo::TaskInfoEntry> GetThreads() noexcept;
  std::span<TaskInfo::TaskInfoEntry> GetExitedThreads() noexcept;

  void AddTask(Ref<TaskInfo> &&task) noexcept;
  u32 RemoveTasksNotInSet(std::span<const gdb::GdbThread> set) noexcept;
  Tid TaskLeaderTid() const noexcept;
  u32 SessionId() const noexcept;
  void SetExitSeen() noexcept;
  TaskInfo *GetTaskByTid(pid_t pid) noexcept;
  UserBreakpoints &GetUserBreakpoints() noexcept;
  /* Create new task meta data for `tid` */
  void CreateNewTask(Tid tid, bool running) noexcept;
  bool HasTask(Tid tid) noexcept;
  bool ReverseResumeTarget(tc::ResumeAction type) noexcept;
  /* Resumes all tasks in this target. */
  bool ResumeTarget(tc::ResumeAction type, std::vector<Tid> *resumedThreads = nullptr) noexcept;
  /* Resumes `task`, which can involve a process more involved than just calling ptrace. */
  void ResumeTask(TaskInfo &task, tc::ResumeAction type) noexcept;
  /* Interrupts/stops all threads in this process space */
  void StopAllTasks(TaskInfo *requestingTask) noexcept;
  void StopAllTasks(TaskInfo *requestingTask, std::function<void()> &&callback) noexcept;
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
  void EmitStoppedAtBreakpoints(LWP lwp, u32 breakpointId, bool allStopped) noexcept;
  void EmitSteppedStop(LWP lwp) noexcept;
  void EmitSteppedStop(LWP lwp, std::string_view message, bool allStopped) noexcept;
  void EmitSignalEvent(LWP lwp, int signal) noexcept;
  void EmitStopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool allStopped,
                   std::vector<int> breakpointsHit) noexcept;
  void EmitBreakpointEvent(std::string_view reason, const UserBreakpoint &bp,
                           std::optional<std::string> message) noexcept;
  tc::ProcessedStopEvent ProcessDeferredStopEvent(TaskInfo &t, DeferToSupervisor &evt) noexcept;

  // Get (&& ||) Create breakpoint locations
  Expected<Ref<BreakpointLocation>, BreakpointError> GetOrCreateBreakpointLocation(AddrPtr addr) noexcept;
  Expected<Ref<BreakpointLocation>, BreakpointError>
  GetOrCreateBreakpointLocation(AddrPtr addr, sym::dw::SourceCodeFile &sourceCodeFile,
                                const sym::dw::LineTableEntry &lte) noexcept;

  Expected<Ref<BreakpointLocation>, BreakpointError>
  GetOrCreateBreakpointLocationWithSourceLoc(AddrPtr addr,
                                             std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept;
  void SetSourceBreakpoints(const std::filesystem::path &sourceFilePath,
                            const Set<BreakpointSpecification> &bps) noexcept;
  void UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
                               std::vector<BreakpointSpecification> &&add,
                               const std::vector<BreakpointSpecification> &remove) noexcept;

  void SetInstructionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept;
  void SetFunctionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept;
  void RemoveBreakpoint(u32 breakpointId) noexcept;

  // Right now, I don't think we care or empathize at all with anything - we just abort/panic, more or less.
  bool TryTerminateGracefully() noexcept;
  bool Detach(bool resume) noexcept;

  bool SetAndCallRunAction(Tid tid, std::shared_ptr<ptracestop::ThreadProceedAction> action) noexcept;
  TraceEvent *CreateTraceEventFromWaitStatus(TaskInfo &task) noexcept;

  void PostExec(const std::string &exe) noexcept;
  /* Check if we have any tasks left in the process space. */
  bool ExecutionHasNotEnded() const noexcept;
  bool IsRunning() const noexcept;

  bool SomeTaskCanBeResumed() const noexcept;

  // Debug Symbols Related Logic
  void RegisterObjectFile(TraceeController *tc, std::shared_ptr<ObjectFile> &&obj, bool isMainExecutable,
                          AddrPtr relocatedBase) noexcept;

  void RegisterSymbolFile(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept;

  // we pass TaskWaitResult here, because want to be able to ASSERT that we just exec'ed.
  // because we actually need to be at the *first* position on the stack, which, if we do at any other time we
  // might (very likely) not be.
  void ReadAuxiliaryVector(TaskInfo &task);
  void SetAuxiliaryVector(ParsedAuxiliaryVector data) noexcept;

  TargetSession GetSessionType() const noexcept;

  Expected<std::unique_ptr<ByteBuffer>, NonFullRead> SafeRead(AddrPtr addr, u64 bytes) noexcept;
  Expected<std::unique_ptr<ByteBuffer>, NonFullRead> SafeRead(std::pmr::memory_resource *allocator, AddrPtr addr,
                                                              u64 bytes) noexcept;
  std::unique_ptr<LeakVector<u8>> ReadToVector(AddrPtr addr, u64 bytes,
                                               std::pmr::memory_resource *resource) noexcept;

  void DeferEvent(Event event) noexcept;
  void ResumeEventHandling() noexcept;
  void InvalidateThreads(int eventTime) noexcept;
  void HandleTracerEvent(TraceEvent *evt) noexcept;
  void OnTearDown() noexcept;
  bool IsReplaySession() const noexcept;

private:
  void DefaultHandler(TraceEvent *evt) noexcept;
  void SetDeferEventHandler() noexcept;

public:
  template <typename T>
  T
  ReadType(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type result;
    u8 *ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto totalRead = 0ull;
    constexpr auto sz = TPtr<T>::SizeOfPointee();
    while (totalRead < sz) {
      const auto readAddress = address.AsVoid() += totalRead;
      const auto readResult = mTraceeInterface->ReadBytes(readAddress, sz - totalRead, ptr + totalRead);
      if (!readResult.WasSuccessful()) {
        PANIC(
          fmt::format("Failed to proc_fs read from {:p} because {}", (void *)address.GetRaw(), strerror(errno)));
      }
      totalRead += readResult.uBytesRead;
    }
    return result;
  }

  template <typename T>
  std::optional<T>
  SafeReadType(TPtr<T> addr)
  {
    typename TPtr<T>::Type result;
    auto ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto totalRead = 0ull;
    constexpr auto sz = TPtr<T>::SizeOfPointee();
    while (totalRead < sz) {
      const auto readAddress = addr.as_void() += totalRead;
      const auto readResult = mTraceeInterface->ReadBytes(readAddress, sz - totalRead, ptr + totalRead);
      if (!readResult.WasSuccessful()) {
        return std::nullopt;
      }
      totalRead += readResult.uBytesRead;
    }
    return result;
  }

  template <typename T>
  void
  Write(TraceePointer<T> address, const T &value)
  {
    auto write_res = mTraceeInterface->Write(address, value);
    if (!write_res.is_expected()) {
      PANIC(fmt::format("Failed to proc_fs write to {:p}", (void *)address.GetRaw()));
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

  void TaskExit(TaskInfo &task, TaskInfo::SupervisorState state, bool notify) noexcept;
  void ExitAll(TaskInfo::SupervisorState state) noexcept;

  // Core event handlers
  tc::ProcessedStopEvent HandleTerminatedBySignal(const Signal &evt) noexcept;
  tc::ProcessedStopEvent HandleStepped(TaskInfo *task, const Stepped &event) noexcept;
  tc::ProcessedStopEvent HandleEntry(TaskInfo *task, const EntryEvent &e) noexcept;
  tc::ProcessedStopEvent HandleThreadCreated(TaskInfo *task, const ThreadCreated &evt,
                                             const RegisterData &register_data) noexcept;
  bool OneRemainingTask() noexcept;
  tc::ProcessedStopEvent HandleBreakpointHit(TaskInfo *task, const BreakpointHitEvent &evt) noexcept;
  tc::ProcessedStopEvent HandleThreadExited(TaskInfo *task, const ThreadExited &evt) noexcept;
  tc::ProcessedStopEvent HandleProcessExit(const ProcessExited &evt) noexcept;
  tc::ProcessedStopEvent HandleFork(const ForkEvent &evt) noexcept;
  tc::ProcessedStopEvent HandleClone(const Clone &evt) noexcept;
  tc::ProcessedStopEvent HandleExec(const Exec &evt) noexcept;

  ui::dap::DebugAdapterClient *GetDebugAdapterProtocolClient() const noexcept;

private:
  void ShutDownDebugAdapterClient() noexcept;
  // Writes breakpoint point and returns the original value found at that address
  Expected<u8, BreakpointError> InstallSoftwareBreakpointLocation(Tid tid, AddrPtr addr) noexcept;
  SupervisorEventHandlerAction mAction{SupervisorEventHandlerAction::Default};
  std::vector<TraceEvent *> mDeferredEvents;
  TraceeController *mVForkedSupervisor{nullptr};
};
} // namespace mdb