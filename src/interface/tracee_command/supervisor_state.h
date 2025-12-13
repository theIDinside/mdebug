/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp.h>
#include <common/typedefs.h>
#include <interface/dap/interface.h>
#include <interface/tracee_command/request_results.h>
#include <symbolication/objfile.h>
#include <task_scheduling.h>
#include <tracee_pointer.h>
#include <utils/leak_vector.h>

// std
#include <memory>
// system
#include <link.h>

using LinkerDebug = r_debug;

namespace mdb {

struct CallStackRequest;
class TaskInfo;

struct LinkerLoaderDebug
{
  int mVersion{ 0 };
  TPtr<LinkerDebug> mRDebug;
};

struct ParsedAuxiliaryVector
{
  AddrPtr mProgramHeaderPointer{ nullptr };
  u32 mProgramHeaderEntrySize{ 0 };
  u32 mProgramHeaderCount{ 0 };
  AddrPtr mEntry{ nullptr };
  AddrPtr mInterpreterBaseAddress{ nullptr };
};

// Asserts if required entries are not found.
struct ParseAuxiliaryOptions
{
  bool requireEntry{ true };
  bool requiresInterpreterBase{ true };
};

ParsedAuxiliaryVector ParsedAuxiliaryVectorData(const Auxv &aux, ParseAuxiliaryOptions options = {}) noexcept;

} // namespace mdb

namespace mdb::sym {
class CallStack;
class Unwinder;
struct UnwinderSymbolFilePair;
} // namespace mdb::sym

namespace mdb::ui::dap {
class DebugAdapterManager;
}

namespace mdb::tc {

template <typename T> using Set = std::unordered_set<T>;

enum class ResumeTarget : u8
{
  None = 0,
  Task = 1,
  AllNonRunningInProcess = 2
};

enum class InterfaceType : std::uint8_t
{
  Ptrace,
  GdbRemote,
  RR
};

enum class ObserverType : u8
{
  AllStop
};

enum class ScheduleAction : u8
{
  Resume,
  Stop
};

struct TaskInfoEntry
{
  Tid mTid;
  RefPtr<TaskInfo> mTask;
};

struct ProcessedStopEvent
{
  bool mShouldResumeAfterProcessing;
  tc::RunType mResumeType = tc::RunType::None;
  std::optional<int> mSignal{ std::nullopt };
  bool mProcessExited{ false };
  bool mThreadExited{ false };
  bool mVForked{ false };
  // TODO: right now, we post stop events a little here and there
  //  we should try to congregate these notifications to happen in a more stream lined fashion
  //  it probably won't be possible to have *all* stop events notified from the same place, but we should
  //  strive to do so, for readability and debuggability. When that refactor should happen, use either this flag,
  //  or remove it and do something else.
  bool mNotifyUser{ false };

  constexpr static auto
  ResumeAny() noexcept
  {
    return ProcessedStopEvent{ true, {} };
  }

  constexpr static auto
  ProcessExited() noexcept
  {
    auto result = ProcessedStopEvent{};
    result.mShouldResumeAfterProcessing = false;
    result.mProcessExited = true;
    return result;
  }

  constexpr static auto
  ThreadExited() noexcept
  {
    auto result = ProcessedStopEvent{};
    result.mShouldResumeAfterProcessing = false;
    result.mThreadExited = true;
    return result;
  }
};

enum class SupervisorType : u8
{
  Native,
  GdbServer,
  RR
};

class SupervisorState
{
protected:
  SessionId mSessionId;
  // This process' parent pid
  pid_t mParentPid{ 0 };
  // The process pid, or the initial task that was spawned for this process
  pid_t mTaskLeader{ 0 };
  // The symbol files that this process is "built of"
  std::vector<std::shared_ptr<SymbolFile>> mSymbolFiles{};
  // The main executable symbol file; the initial executable binary, i.e. the one passed to `execve` at some point.
  std::shared_ptr<SymbolFile> mMainExecutable{ nullptr };
  // The tasks that exist in this "process space". Since tasks often are looked up by tid, before we want to do
  // something with it we save an indirection by storing the tid inline here, same goes for mExitedThreads.
  std::vector<TaskInfoEntry> mThreads{};

  std::vector<TaskInfoEntry> mExitedThreads{};

  // The breakpoints set by the user
  ProcessBreakpointsManager mUserBreakpoints;

  // Emits "all stopped" event to all subscribers
  Publisher<void> mAllStopPublisher{};
  // Emits "new module/new dynamic library" event to all subscribers
  Publisher<SymbolFile *> mNewObjectFilePublisher{};

  Publisher<void> mOnExecOrExitPublisher{};

  // The Debug Adapter Protocol client, by which we communicate with. It handles the communication with the
  // Debug Adapter implementation.
  // TODO: at some point it should be configurable, to use other channels than just stdio. Should be fairly
  // trivial.
  ui::dap::DebugAdapterManager *mDebugAdapterClient{ nullptr };

  // Monotonically increasing "variable reference" as defined by the debug adapter protocol.
  int mNextVariableReference = 0;

  BreakpointBehavior mBreakpointBehavior{ BreakpointBehavior::StopAllThreadsWhenHit };

  // The currently installed Stop handler
  UniquePtr<TaskScheduler> mScheduler;
  // an unwinder that always returns sym::UnwindInfo* = nullptr
  sym::Unwinder *mNullUnwinder;

  // Protect against being configured multiple times by Debug Adapter client. Vscode seems to send multiple of
  // these, sometimes. Yay. Cool.
  bool mIsConfigured{ false };
  bool mIsExited{ false };
  bool mIsDisconnected{ false };

  // The auxilliary vector of the application/process being debugged. Contains things like entry, interpreter base,
  // what the executable file was etc:

  // The base address that defines the interpreter that we use. It gives us the system path to where we can load
  // and parse debug symbol information from the system linker, so that we can install breakpoints in specific
  // places when the linker loads libraries. This is how we track what dynamic libraries is being used by a process

  // The entry point of an executable (usually the first instruction of the function `_start` for c-run time/posix
  // applications on Linux)
  ParsedAuxiliaryVector mParsedAuxiliaryVector;
  LinkerLoaderDebug mLinkerDebugData;

  std::function<bool(SupervisorState *supervisor)> mOnConfigurationDoneCallback;

public:
  const SupervisorType mSupervisorType;

public:
  SupervisorState(SupervisorType type, Tid taskLeader, ui::dap::DebugAdapterManager *client) noexcept;
  virtual ~SupervisorState() noexcept = default;

  sym::Unwinder *GetNullUnwinder() const noexcept;
  void OnForkFrom(const SupervisorState &parent) noexcept;
  void SetParent(Pid parentPid) noexcept;
  void SetTaskLeader(Tid taskLeaderTid) noexcept;
  void SetSessionId(SessionId sessionId) noexcept;
  Publisher<void> &GetOnExecOrExitPublisher() noexcept;

  ProcessBreakpointsManager &
  GetUserBreakpoints() noexcept
  {
    return mUserBreakpoints;
  }

  const ProcessBreakpointsManager &
  GetUserBreakpoints() const noexcept
  {
    return mUserBreakpoints;
  }

  // Emit event FOO at stop
  void EmitStoppedAtBreakpoints(LWP lwp, u32 breakpointId, bool allStopped) noexcept;
  void EmitStepNotification(LWP lwp) noexcept;
  void EmitSteppedStop(LWP lwp, std::string_view message, bool allStopped) noexcept;
  void EmitSignalEvent(LWP lwp, int signal) noexcept;
  void EmitStopped(Tid tid,
    ui::dap::StoppedReason reason,
    std::string_view message,
    bool allStopped,
    std::vector<int> breakpointsHit) noexcept;
  void EmitBreakpointEvent(
    std::string_view reason, const UserBreakpoint &bp, std::optional<std::string> message) noexcept;
  void EmitAllStopped() noexcept;

  u32 ThreadsCount() const noexcept;

  // Get (&& ||) Create breakpoint locations
  Expected<Ref<BreakpointLocation>, BreakpointError> GetOrCreateBreakpointLocation(AddrPtr addr) noexcept;
  Expected<Ref<BreakpointLocation>, BreakpointError> GetOrCreateBreakpointLocation(
    AddrPtr addr, sym::dw::SourceCodeFile &sourceCodeFile, const sym::dw::LineTableEntry &lte) noexcept;

  Expected<Ref<BreakpointLocation>, BreakpointError> GetOrCreateBreakpointLocationWithSourceLoc(
    AddrPtr addr, std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept;
  void SetSourceBreakpoints(
    const std::filesystem::path &sourceFilePath, const Set<BreakpointSpecification> &bps) noexcept;
  void UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
    std::vector<BreakpointSpecification> &&add,
    const std::vector<BreakpointSpecification> &remove) noexcept;

  void SetInstructionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept;
  void SetFunctionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept;
  void RemoveBreakpoint(u32 breakpointId) noexcept;

  void LoadBreakpoints(SharedPtr<SessionBreakpoints> breakpoints) noexcept;
  void DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>> &&newSymbolFiles) noexcept;

  bool CheckBreakpointLocationsForSymbolFile(
    SymbolFile &symbolFile, UserBreakpoint &user, std::vector<Ref<BreakpointLocation>> &locs) noexcept;

  SessionId
  GetSessionId() const noexcept
  {
    return mSessionId;
  }

  void SetExitSeen() noexcept;

  constexpr Tid
  TaskLeaderTid() const noexcept
  {
    return mTaskLeader;
  }

  std::span<std::shared_ptr<SymbolFile>> GetSymbolFiles() noexcept;
  // Look up if the debugger has parsed symbol object file with `path` and return it. Otherwise returns nullptr
  std::shared_ptr<SymbolFile> LookupSymbolFile(const Path &path) noexcept;
  // Return the entry address (usually address of _start) for this executable
  AddrPtr EntryAddress() const noexcept;
  /** Install breakpoints in the loader (ld.so). Used to determine what shared libraries tracee consists of. */
  void InstallDynamicLoaderBreakpoints(AddrPtr mappedDynamicSectionAddress) noexcept;

  void ConfigureBreakpointBehavior(BreakpointBehavior behavior) noexcept;
  void SetLinkerDebugData(int version, AddrPtr rDebugAddr);

  void TearDown(bool killProcess) noexcept;
  bool IsExited() const noexcept;
  bool IsDisconnected() const noexcept;
  void ConfigureDapClient(ui::dap::DebugAdapterManager *client) noexcept;
  void Disconnect(bool terminate) noexcept;

  void OnTearDown() noexcept;

  TaskInfo *GetTaskByTid(pid_t pid) noexcept;
  /* Create new task meta data for `tid` */
  void CreateNewTask(Tid tid, std::optional<std::string_view> name, bool running) noexcept;
  bool HasTask(Tid tid) noexcept;

  /* Resumes all tasks in this target. */
  bool ResumeTarget(tc::RunType type, std::vector<Tid> *resumedThreads = nullptr) noexcept;
  /* Resumes `task`, which can involve a process more involved than just calling ptrace. */
  void ResumeTask(TaskInfo &task, tc::RunType type) noexcept;
  /* Interrupts/stops all threads in this process space */
  void StopAllTasks() noexcept;
  void StopAllTasks(std::function<void()> &&callback) noexcept;
  void ScheduleResume(TaskInfo &task, tc::RunType type) noexcept;

  // Cache the register contents for `task` and return the program counter.
  AddrPtr CacheAndGetPcFor(TaskInfo &task) noexcept;

  // Read (null-terminated) string starting at `address` in tracee VM space
  std::optional<std::string> ReadString(TraceePointer<char> address) noexcept;
  // Get the unwinder for `pc` - if no such unwinder exists, the "NullUnwinder" is returned, an unwinder that
  // always returns UnwindInfo* = `nullptr` results. This is to not have to do nullchecks against the Unwinder
  // itself.
  sym::UnwinderSymbolFilePair GetUnwinderUsingPc(AddrPtr pc) noexcept;
  sym::CallStack &BuildCallFrameStack(TaskInfo &task, const CallStackRequest &req) noexcept;

  // Get "bottom most" frame
  sym::Frame GetCurrentFrame(TaskInfo &task) noexcept;
  std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>> FindFunctionByPc(AddrPtr addr) noexcept;
  SymbolFile *FindObjectByPc(AddrPtr addr) noexcept;

  void PostExec(const std::string &exe, bool stopAtEntry, bool installDynamicLoaderBreakpoints = true) noexcept;

  Expected<std::unique_ptr<ByteBuffer>, NonFullRead> SafeRead(AddrPtr addr, u64 bytes) noexcept;
  Expected<std::unique_ptr<ByteBuffer>, NonFullRead> SafeRead(
    std::pmr::memory_resource *allocator, AddrPtr addr, u64 bytes) noexcept;

  std::unique_ptr<LeakVector<u8>> ReadToVector(
    AddrPtr addr, u64 bytes, std::pmr::memory_resource *resource) noexcept;

  std::optional<std::string> ReadNullTerminatedString(TraceePointer<char> address) noexcept;

  template <typename T>
  T
  ReadType(TraceePointer<T> address) noexcept
  {
    MDB_ASSERT(address != nullptr, "Can't read from nullptr address (0)");
    typename TPtr<T>::Type result;
    u8 *ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto totalRead = 0ull;
    constexpr auto sz = TPtr<T>::SizeOfPointee();
    while (totalRead < sz) {
      const auto readAddress = address.AsVoid() += totalRead;
      const auto readResult = DoReadBytes(readAddress, sz - totalRead, ptr + totalRead);
      if (!readResult.WasSuccessful()) {
        PANIC(std::format("Target-read failed at {:p} because {}", (void *)address.GetRaw(), strerror(errno)));
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
    if (addr == nullptr) {
      return std::nullopt;
    }
    auto ptr = static_cast<u8 *>(static_cast<void *>(&result));
    auto totalRead = 0ull;
    constexpr auto sz = TPtr<T>::SizeOfPointee();
    while (totalRead < sz) {
      const auto readAddress = addr.AsVoid() += totalRead;
      const auto readResult = DoReadBytes(readAddress, sz - totalRead, ptr + totalRead);
      if (!readResult.WasSuccessful()) {
        return std::nullopt;
      }
      totalRead += readResult.uBytesRead;
    }
    return result;
  }

  template <typename T>
  u64
  ReadIntoVector(AddrPtr address, u32 count, std::vector<T> &result) noexcept
  {
    result.reserve(count);
    for (u32 i = 0; i < count; ++i) {
      if (auto readResult = SafeReadType(address.As<T>()); readResult.has_value()) {
        result.push_back(readResult.value());
      } else {
        break;
      }
      address += sizeof(T);
    }

    return result.size() * sizeof(T);
  }

  bool WriteBytes(AddrPtr address, std::span<u8> bytes) noexcept;

  template <typename T>
  void
  Write(TraceePointer<T> address, const T &value)
  {
    auto write_res = DoWrite(address, value);
    if (!write_res.is_expected()) {
      PANIC(std::format("Failed to proc_fs write to {:p}", (void *)address.GetRaw()));
    }
  }

  void HandleBreakpointHit(TaskInfo &task, const RefPtr<BreakpointLocation> &breakpointLocation) noexcept;
  void HandleExec(TaskInfo &task, const std::string &execFile) noexcept;
  // HandleFork is handled so differently from session type to session type, that it has to be virtual

  void CacheRegistersFor(TaskInfo &t, bool forceRefresh = false) noexcept;

  void OnSharedObjectEvent() noexcept;

  /* Interrupts/stops all threads in this process space */
  bool IsAllStopped() const noexcept;

  constexpr BreakpointBehavior
  GetBreakpointBehavior() const noexcept
  {
    return mBreakpointBehavior;
  }

  // Debug Symbols Related Logic
  void RegisterObjectFile(
    SupervisorState *tc, std::shared_ptr<ObjectFile> &&obj, bool isMainExecutable, AddrPtr relocatedBase) noexcept;

  void RegisterSymbolFile(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept;

  void SetAuxiliaryVector(ParsedAuxiliaryVector data) noexcept;
  void PostTaskExit(TaskInfo &task, bool notify) noexcept;

  std::span<TaskInfoEntry> GetThreads() noexcept;
  ui::dap::DebugAdapterManager *GetDebugAdapterProtocolClient() const noexcept;
  bool SetAndCallRunAction(Tid tid, std::shared_ptr<ptracestop::ThreadProceedAction> action) noexcept;
  bool IsRunning() const noexcept;
  void OnConfigurationDone(std::function<bool(SupervisorState *supervisor)> &&done) noexcept;
  bool ConfigurationDone() noexcept;

protected:
  Expected<u8, BreakpointError> InstallSoftwareBreakpointLocation(Tid tid, AddrPtr addr) noexcept;
  void ShutDownDebugAdapterClient() noexcept;

  enum class LinkerReadResult : u8
  {
    InconsistentState,
    Error,
    Ok,
  };
  LinkerReadResult ReadLinkerInformation(
    const r_debug &debug, std::vector<ObjectFileDescriptor> &objects) noexcept;

  // IMPLEMENTATION CUSTOMIZATION POINTS
private:
  // Called after a fork for the creation of a new process supervisor
  virtual void HandleFork(TaskInfo &parentTask, pid_t child, bool vFork) noexcept = 0;
  virtual mdb::Expected<Auxv, Error> DoReadAuxiliaryVector() noexcept = 0;
  virtual void InitRegisterCacheFor(const TaskInfo &task) noexcept = 0;

protected:
  virtual bool PerformShutdown() noexcept = 0;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  virtual TaskExecuteResponse InstallBreakpoint(Tid tid, AddrPtr addr) noexcept = 0;

public:
  virtual TaskExecuteResponse ReadRegisters(TaskInfo &t) noexcept = 0;
  virtual TaskExecuteResponse WriteRegisters(TaskInfo &t, void *data, size_t length) noexcept = 0;
  virtual TaskExecuteResponse SetRegister(
    TaskInfo &t, size_t registerNumber, void *data, size_t length) noexcept = 0;
  // Used for normal debugging operations. Retrieving special registers is uninteresting from a debugger interface
  // perspective and as such should be handled specifically. For instance, unwinding the stack which is a very
  // common operation, relies solely on user registers and never anything else. locations of types and objects, are
  // defined by DWARF operations and these also, never use special registers. If this changes, just change this
  // interface to account for special registers as well.
  virtual u64 GetUserRegister(const TaskInfo &t, size_t registerNumber) noexcept = 0;

  virtual TaskExecuteResponse DoDisconnect(bool terminate) noexcept = 0;
  virtual std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept;
  virtual ReadResult DoReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept = 0;
  virtual TraceeWriteResult DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept = 0;

  virtual TaskExecuteResponse EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept = 0;
  virtual TaskExecuteResponse DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept = 0;

  virtual bool Pause(Tid tid) noexcept = 0;

  // Can (possibly) modify state in `t`
  virtual TaskExecuteResponse StopTask(TaskInfo &t) noexcept = 0;
  virtual void DoResumeTask(TaskInfo &t, RunType type) noexcept = 0;
  virtual bool DoResumeTarget(RunType type) noexcept = 0;
  virtual void AttachSession(ui::dap::DebugAdapterSession &session) noexcept = 0;
  virtual bool ReverseResumeTarget(tc::RunType type) noexcept;
};

} // namespace mdb::tc

template <> struct std::formatter<mdb::tc::RunType>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const mdb::tc::RunType &type, FormatContext &ctx) const
  {
    using enum mdb::tc::RunType;
    switch (type) {
    case Step:
      return std::format_to(ctx.out(), "RunType::Step");
    case Continue:
      return std::format_to(ctx.out(), "RunType::Continue");
    case SyscallContinue:
      return std::format_to(ctx.out(), "RunType::SyscallContinue");
    case Unknown:
      return std::format_to(ctx.out(), "RunType::UNKNOWN");
    }
  }
};

template <> struct std::formatter<mdb::tc::ResumeTarget>
{
  BASIC_PARSE

  template <typename FormatContext>
  constexpr auto
  format(const mdb::tc::ResumeTarget &tgt, FormatContext &ctx) const
  {

    switch (tgt) {
    case mdb::tc::ResumeTarget::Task:
      return std::format_to(ctx.out(), "ResumeTarget::Task");
    case mdb::tc::ResumeTarget::AllNonRunningInProcess:
      return std::format_to(ctx.out(), "ResumeTarget::AllNonRunningInProcess");
    case mdb::tc::ResumeTarget::None:
      return std::format_to(ctx.out(), "ResumeTarget::None");
    default:
      static_assert(mdb::always_false<FormatContext>, "All cases not handled");
    }
  }
};