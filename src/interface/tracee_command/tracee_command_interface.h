/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/macros.h>
#include <interface/remotegdb/target_description.h>
#include <register_description.h>
#include <tracee_pointer.h>
#include <utils/expected.h>
#include <utils/immutable.h>
#include <utils/logger.h>

// system
#include <link.h>
#include <sys/ptrace.h>

// std
#include <print>

using namespace std::string_view_literals;
namespace mdb {
class TraceeController;
class TaskInfo;
class SymbolFile;

class BreakpointLocation;
} // namespace mdb

namespace mdb::ui::dap {
struct Thread;
};

namespace mdb::gdb {
class RemoteConnection;
struct RemoteSettings;
} // namespace mdb::gdb

/// Tracee Control
namespace mdb::tc {

enum class ResumeTarget : u8
{
  None = 0,
  Task = 1,
  AllNonRunningInProcess = 2
};

struct ResumeAction
{
  RunType mResumeType;
  ResumeTarget mResumeTarget{ ResumeTarget::Task };
  int mDeliverSignal{ 0 };

  constexpr
  operator __ptrace_request() const noexcept
  {
    ASSERT(mResumeType != RunType::Unknown, "Invalid ptrace resume operation");
    return static_cast<__ptrace_request>(mResumeType);
  }
};

enum class ShouldProceed
{
  DoNothing,
  Resume,
  StopAll
};

struct ProcessedStopEvent
{
  bool mShouldResumeAfterProcessing;
  std::optional<tc::ResumeAction> mResumeAction{};
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
    return ProcessedStopEvent{ false, std::nullopt, true };
  }

  constexpr static auto
  ThreadExited() noexcept
  {
    return ProcessedStopEvent{ false, std::nullopt, false, true };
  }
};

struct TraceeWriteResult
{
  bool mWasSuccessful;
  union
  {
    u32 uBytesWritten;
    i32 uSysErrorNumber;
  };

  constexpr static TraceeWriteResult
  Ok(u32 bytes_written) noexcept
  {
    return TraceeWriteResult{ .mWasSuccessful = true, .uBytesWritten = bytes_written };
  }

  constexpr static TraceeWriteResult
  Error(int sys_error) noexcept
  {
    return TraceeWriteResult{ .mWasSuccessful = false, .uSysErrorNumber = sys_error };
  }
};

enum class ReadResultType : i8
{
  SystemError = -1,
  EoF = 0,
  OK = 1,
  DebuggerError
};

enum class ApplicationError : u32
{
  TargetIsRunning
};

struct ReadResult
{
  ReadResultType mResultType;
  union
  {
    u32 uBytesRead;
    i32 uSysErrorNumber;
    ApplicationError uError;
  };

  constexpr bool
  WasSuccessful() const noexcept
  {
    return mResultType == ReadResultType::OK;
  }

  constexpr static ReadResult
  Ok(u32 bytesRead) noexcept
  {
    return ReadResult{ .mResultType = ReadResultType::OK, .uBytesRead = bytesRead };
  }
  constexpr static ReadResult
  SystemError(int sysErrorNumber) noexcept
  {
    return ReadResult{ .mResultType = ReadResultType::SystemError, .uSysErrorNumber = sysErrorNumber };
  }

  constexpr static ReadResult
  AppError(ApplicationError error) noexcept
  {
    return ReadResult{ .mResultType = ReadResultType::DebuggerError, .uError = error };
  }
  constexpr static ReadResult
  EoF() noexcept
  {
    return ReadResult{ .mResultType = ReadResultType::EoF, .uBytesRead = 0 };
  }
};

struct PtraceCfg
{
  pid_t tid;
};

struct GdbRemoteCfg
{
  std::string host;
  int port;
};

enum class TaskExecuteResult
{
  Ok,
  Error,
  None,
};

struct TaskExecuteResponse
{
  TaskExecuteResult kind;
  union
  {
    int sys_errno;
    u32 data;
  };

  constexpr static TaskExecuteResponse
  Error(int sys_error) noexcept
  {
    return TaskExecuteResponse{ .kind = TaskExecuteResult::Error, .sys_errno = sys_error };
  }

  constexpr static TaskExecuteResponse
  Ok(u32 data = 0) noexcept
  {
    return TaskExecuteResponse{ .kind = TaskExecuteResult::Ok, .data = data };
  }

  constexpr bool
  is_ok() const noexcept
  {
    return kind == TaskExecuteResult::Ok;
  }

  constexpr
  operator bool() const noexcept
  {
    return is_ok();
  }
};

std::string_view to_str(RunType type) noexcept;

using InterfaceConfig = std::variant<PtraceCfg, GdbRemoteCfg>;

struct WriteError
{
  AddrPtr mAddress;
  u32 mBytesWritten;
  int mSysErrorNumber;
};

struct ObjectFileDescriptor
{
  std::filesystem::path mPath;
  AddrPtr mAddress;
};

struct AuxvElement
{
  u64 mId;
  u64 mEntry;
};

struct Auxv
{
  std::vector<AuxvElement> mContents;
};

struct Error
{
  Immutable<std::optional<int>> mSysErrorNumber;
  Immutable<std::string_view> mErrorMessage;
  Immutable<std::optional<std::string>> mError{};
};

class TraceeCommandInterface;
using Interface = std::unique_ptr<TraceeCommandInterface>;

enum class TraceeInterfaceType
{
  Ptrace,
  GdbRemote
};

// Abstract base class & interface for controlling and querying tracees
// PtraceCommander is the native interface
// GdbRemoteCommander is the gdb remote protocol interface
class TraceeCommandInterface
{
protected:
  TraceeController *mControl{ nullptr };

public:
  Immutable<TargetFormat> mFormat;
  Immutable<std::shared_ptr<gdb::ArchictectureInfo>> mArchInfo;
  TraceeInterfaceType mType;
  TPtr<r_debug_extended> tracee_r_debug{ nullptr };

  NO_COPY(TraceeCommandInterface);
  TraceeCommandInterface(
    TargetFormat format, std::shared_ptr<gdb::ArchictectureInfo> &&arch_info, TraceeInterfaceType type) noexcept;
  virtual ~TraceeCommandInterface() noexcept = default;
  virtual ReadResult ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept = 0;
  virtual TraceeWriteResult WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept = 0;

  constexpr TraceeWriteResult
  WriteBytes(AddrPtr addr, std::span<u8> bytes) noexcept
  {
    return WriteBytes(addr, bytes.data(), bytes.size_bytes());
  }

  // Reverse execute. `onlyStep` if we should be stepping. If false, do reverse execution.
  virtual TaskExecuteResponse ReverseContinue(bool onlyStep) noexcept;
  // Can (possibly) modify state in `t`
  virtual TaskExecuteResponse ResumeTask(TaskInfo &t, ResumeAction run) noexcept = 0;

  // TODO(simon): remove `tc` from interface. we now hold on to one in this type instead
  /** `resumedThreads` is an optional out parameter consisting of the tids of the threads that got resumed. */
  virtual TaskExecuteResponse ResumeTarget(
    TraceeController *tc, ResumeAction run, std::vector<Tid> *resumedThreads) noexcept = 0;
  // Can (possibly) modify state in `t`
  virtual TaskExecuteResponse StopTask(TaskInfo &t) noexcept = 0;

  virtual TaskExecuteResponse EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept = 0;
  virtual TaskExecuteResponse DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept = 0;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  virtual TaskExecuteResponse InstallBreakpoint(Tid tid, AddrPtr addr) noexcept = 0;

  virtual TaskExecuteResponse ReadRegisters(TaskInfo &t) noexcept = 0;
  virtual TaskExecuteResponse WriteRegisters(const user_regs_struct &input) noexcept = 0;
  virtual TaskExecuteResponse SetProgramCounter(const TaskInfo &t, AddrPtr addr) noexcept = 0;
  virtual TaskExecuteResponse Disconnect(bool terminate) noexcept = 0;

  virtual bool PerformShutdown() noexcept = 0;

  virtual std::string_view GetThreadName(Tid tid) noexcept = 0;

  /// Called after we've processed an exec, which during a native debug session, we need to acquire some proc fs
  /// files, for instance
  virtual bool OnExec() noexcept = 0;

  // Called after a fork for the creation of a new process supervisor
  virtual Interface OnFork(SessionId pid) noexcept = 0;
  // Returns true|false if the process that forked, should be resumed immediately.
  // In cases like RR, where we control the entire application across many processes, we don't actually want to let
  // the process resume. Because we need to do a full configuration first (and set potential breakpoints, according
  // to how DAP defines the initialization process). In those cases we want to halt (because the session will be
  // resumed once the new process has been configured and has it's `ConfigurationDone` request performed.)
  virtual bool PostFork(TraceeController *parent) noexcept = 0;

  virtual Tid TaskLeaderTid() const noexcept = 0;
  virtual std::optional<Path> ExecedFile() noexcept = 0;
  virtual std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept = 0;

  virtual std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept = 0;
  virtual mdb::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept = 0;

  virtual bool TargetManagesBreakpoints() noexcept;
  TaskExecuteResponse DoDisconnect(bool terminate) noexcept;

  static Interface CreateCommandInterface(const InterfaceConfig &config) noexcept;
  std::optional<std::string> ReadNullTerminatedString(TraceePointer<char> address) noexcept;
  void SetTarget(TraceeController *tc) noexcept;

  virtual bool
  IsAllStopSession() noexcept
  {
    return false;
  }

  template <typename T>
  mdb::Expected<T, std::string_view>
  ReadType(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type result;
    auto totalRead = 0ull;
    constexpr auto sz = TPtr<T>::SizeOfPointee();
    u8 *ptr = static_cast<u8 *>((void *)std::addressof(result));
    while (totalRead < sz) {
      auto readResult = ReadBytes(address.AsVoid(), sz - totalRead, ptr + totalRead);
      switch (readResult.mResultType) {
      case ReadResultType::SystemError:
        return mdb::unexpected<std::string_view>(strerror(readResult.uSysErrorNumber));
      case ReadResultType::EoF:
        return mdb::unexpected<std::string_view>("End of file reported"sv);
      case ReadResultType::DebuggerError:
        TODO("implement handling of 'DebuggerError' in read_type");
      case ReadResultType::OK:
        totalRead += readResult.uBytesRead;
        if (totalRead == sz) {
          break;
        }
        address += readResult.uBytesRead;
        continue;
      }
    }
    return mdb::expected<T>(result);
  }

  template <typename T>
  mdb::Expected<u32, WriteError>
  Write(TraceePointer<T> address, const T &value)
  {
    auto totalWritten = 0ull;
    auto sz = address.SizeOfPointee();
    const u8 *ptr = static_cast<u8 *>(std::addressof(value));

    while (totalWritten < sz) {
      const auto written = WriteBytes(address + totalWritten, ptr + totalWritten, sz - totalWritten);
      if (written.mWasSuccessful) {
        totalWritten += written.uBytesWritten;
      } else {
        auto addressValue = reinterpret_cast<std::uintptr_t>(ptr) + totalWritten;
        return mdb::unexpected(WriteError{ .mAddress = AddrPtr{ addressValue },
          .mBytesWritten = totalWritten,
          .mSysErrorNumber = written.uSysErrorNumber });
      }
    }
    return mdb::expected(static_cast<u32>(totalWritten));
  }

  inline constexpr TraceeController *
  GetSupervisor() noexcept
  {
    return mControl;
  }

  virtual bool
  IsReplaySession() const noexcept
  {
    return false;
  }
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