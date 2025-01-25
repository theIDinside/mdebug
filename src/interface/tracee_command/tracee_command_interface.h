/** LICENSE TEMPLATE */
#pragma once
#include "interface/remotegdb/target_description.h"
#include "register_description.h"
#include "tracee_pointer.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/logger.h"
#include "utils/macros.h"
#include <link.h>
#include <sys/ptrace.h>

using namespace std::string_view_literals;
class TraceeController;
struct TaskInfo;
class SymbolFile;

class BreakpointLocation;

namespace ui::dap {
struct Thread;
};

namespace gdb {
class RemoteConnection;
struct RemoteSettings;
} // namespace gdb

/// Tracee Control
namespace tc {

enum class RunType : u8
{
  Unknown = 0b0000,
  None = Unknown,
  Step = PTRACE_SINGLESTEP,
  Continue = PTRACE_CONT,
  SyscallContinue = PTRACE_SYSCALL,
};

enum class ResumeTarget : u8
{
  None = 0,
  Task = 1,
  AllNonRunningInProcess = 2
};

struct ResumeAction
{
  RunType type;
  ResumeTarget target;
  int mDeliverSignal;

  constexpr
  operator __ptrace_request() const noexcept
  {
    ASSERT(type != RunType::Unknown, "Invalid ptrace resume operation");
    return static_cast<__ptrace_request>(type);
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
  bool should_resume;
  std::optional<tc::ResumeAction> res;
  bool mProcessExited{false};
  bool mThreadExited{false};
  bool mVForked{false};
  // TODO: right now, we post stop events a little here and there
  //  we should try to congregate these notifications to happen in a more stream lined fashion
  //  it probably won't be possible to have *all* stop events notified from the same place, but we should
  //  strive to do so, for readability and debuggability. When that refactor should happen, use either this flag,
  //  or remove it and do something else.
  bool mNotifyUser{false};

  constexpr static auto
  ResumeAny() noexcept
  {
    return ProcessedStopEvent{true, {}};
  }

  constexpr static auto
  ProcessExited() noexcept
  {
    return ProcessedStopEvent{false, std::nullopt, true};
  }

  constexpr static auto
  ThreadExited() noexcept
  {
    return ProcessedStopEvent{false, std::nullopt, false, true};
  }
};

struct TraceeWriteResult
{
  bool success;
  union
  {
    u32 bytes_written;
    i32 sys_errno;
  };

  constexpr static TraceeWriteResult
  Ok(u32 bytes_written) noexcept
  {
    return TraceeWriteResult{.success = true, .bytes_written = bytes_written};
  }

  constexpr static TraceeWriteResult
  Error(int sys_error) noexcept
  {
    return TraceeWriteResult{.success = false, .sys_errno = sys_error};
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
  ReadResultType op_result;
  union
  {
    u32 bytes_read;
    i32 sys_errno;
    ApplicationError error;
  };

  constexpr bool
  success() const noexcept
  {
    return op_result == ReadResultType::OK;
  }

  constexpr static ReadResult
  Ok(u32 bytes_read) noexcept
  {
    return ReadResult{.op_result = ReadResultType::OK, .bytes_read = bytes_read};
  }
  constexpr static ReadResult
  SystemError(int sys_error) noexcept
  {
    return ReadResult{.op_result = ReadResultType::SystemError, .sys_errno = sys_error};
  }

  constexpr static ReadResult
  AppError(ApplicationError err) noexcept
  {
    return ReadResult{.op_result = ReadResultType::DebuggerError, .error = err};
  }
  constexpr static ReadResult
  EoF() noexcept
  {
    return ReadResult{.op_result = ReadResultType::EoF, .bytes_read = 0};
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
    return TaskExecuteResponse{.kind = TaskExecuteResult::Error, .sys_errno = sys_error};
  }

  constexpr static TaskExecuteResponse
  Ok(u32 data = 0) noexcept
  {
    return TaskExecuteResponse{.kind = TaskExecuteResult::Ok, .data = data};
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
  AddrPtr address;
  u32 bytes_written;
  int sys_errno;
};

struct ObjectFileDescriptor
{
  std::filesystem::path path;
  AddrPtr address;
};

struct AuxvElement
{
  u64 id;
  u64 entry;
};

struct Auxv
{
  std::vector<AuxvElement> vector;
};

struct Error
{
  Immutable<std::optional<int>> sys_errno;
  Immutable<std::string_view> err_msg;
  Immutable<std::optional<std::string>> err{};
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
  TraceeController *tc{nullptr};

public:
  Immutable<TargetFormat> mFormat;
  Immutable<std::shared_ptr<gdb::ArchictectureInfo>> mArchInfo;
  TraceeInterfaceType mType;
  TPtr<r_debug_extended> tracee_r_debug{nullptr};

  NO_COPY(TraceeCommandInterface);
  TraceeCommandInterface(TargetFormat format, std::shared_ptr<gdb::ArchictectureInfo> &&arch_info,
                         TraceeInterfaceType type) noexcept;
  virtual ~TraceeCommandInterface() noexcept = default;
  virtual ReadResult ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept = 0;
  virtual TraceeWriteResult WriteBytes(AddrPtr addr, u8 *buf, u32 size) noexcept = 0;
  virtual TaskExecuteResponse ReverseContinue() noexcept;
  // Can (possibly) modify state in `t`
  virtual TaskExecuteResponse ResumeTask(TaskInfo &t, ResumeAction run) noexcept = 0;
  // TODO(simon): remove `tc` from interface. we now hold on to one in this type instead
  virtual TaskExecuteResponse ResumeTarget(TraceeController *tc, ResumeAction run) noexcept = 0;
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
  virtual bool Initialize() noexcept = 0;

  virtual std::string_view GetThreadName(Tid tid) noexcept = 0;

  /// Called after we've processed an exec, which during a native debug session, we need to acquire some proc fs
  /// files, for instance
  virtual bool OnExec() noexcept = 0;

  // Called after a fork for the creation of a new process supervisor
  virtual Interface OnFork(Pid pid) noexcept = 0;

  virtual Tid TaskLeaderTid() const noexcept = 0;
  virtual std::optional<Path> ExecedFile() noexcept = 0;
  virtual std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept = 0;

  virtual std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept = 0;
  virtual utils::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept = 0;

  virtual bool TargetManagesBreakpoints() noexcept;
  TaskExecuteResponse DoDisconnect(bool terminate) noexcept;

  static Interface CreateCommandInterface(const InterfaceConfig &config) noexcept;
  std::optional<std::string> ReadNullTerminatedString(TraceePointer<char> address, u32 buffer_size = 128) noexcept;
  void SetTarget(TraceeController *tc) noexcept;

  template <typename T>
  utils::Expected<T, std::string_view>
  ReadType(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type t_result;
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    u8 *ptr = static_cast<u8 *>((void *)std::addressof(t_result));
    while (total_read < sz) {
      auto read_result = ReadBytes(address.as_void(), sz - total_read, ptr + total_read);
      switch (read_result.op_result) {
      case ReadResultType::SystemError:
        return utils::unexpected<std::string_view>(strerror(read_result.sys_errno));
      case ReadResultType::EoF:
        return utils::unexpected<std::string_view>("End of file reported"sv);
      case ReadResultType::DebuggerError:
        TODO("implement handling of 'DebuggerError' in read_type");
      case ReadResultType::OK:
        total_read += read_result.bytes_read;
        if (total_read == sz) {
          break;
        }
        address += read_result.bytes_read;
        continue;
      }
    }
    return utils::expected<T>(t_result);
  }

  template <typename T>
  utils::Expected<u32, WriteError>
  Write(TraceePointer<T> address, const T &value)
  {
    auto total_written = 0ull;
    auto sz = address.type_size();
    const u8 *ptr = static_cast<u8 *>(std::addressof(value));

    while (total_written < sz) {
      const auto written = WriteBytes(address + total_written, ptr + total_written, sz - total_written);
      if (written.success) {
        total_written += written.bytes_written;
      } else {
        auto addr_value = reinterpret_cast<std::uintptr_t>(ptr) + total_written;
        return utils::unexpected(WriteError{
          .address = AddrPtr{addr_value}, .bytes_written = total_written, .sys_errno = written.err.sys_error_num});
      }
    }
    return utils::expected(static_cast<u32>(total_written));
  }

  inline constexpr TraceeController *
  GetSupervisor() noexcept
  {
    return tc;
  }
};

} // namespace tc

namespace fmt {

template <> struct formatter<tc::RunType>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const tc::RunType &type, FormatContext &ctx) const
  {
    switch (type) {
    case tc::RunType::Step:
      return fmt::format_to(ctx.out(), "RunType::Step");
    case tc::RunType::Continue:
      return fmt::format_to(ctx.out(), "RunType::Continue");
    case tc::RunType::SyscallContinue:
      return fmt::format_to(ctx.out(), "RunType::SyscallContinue");
    case tc::RunType::Unknown:
      return fmt::format_to(ctx.out(), "RunType::UNKNOWN");
    }
  }
};

template <> struct formatter<tc::ResumeTarget>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  constexpr auto
  format(const tc::ResumeTarget &tgt, FormatContext &ctx) const
  {

    switch (tgt) {
    case tc::ResumeTarget::Task:
      return fmt::format_to(ctx.out(), "ResumeTarget::Task");
    case tc::ResumeTarget::AllNonRunningInProcess:
      return fmt::format_to(ctx.out(), "ResumeTarget::AllNonRunningInProcess");
    case tc::ResumeTarget::None:
      return fmt::format_to(ctx.out(), "ResumeTarget::None");
    default:
      static_assert(always_false<FormatContext>, "All cases not handled");
    }
  }
};

} // namespace fmt