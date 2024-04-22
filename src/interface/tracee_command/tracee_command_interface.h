#pragma once
#include "utils/expected.h"
#include "utils/macros.h"
#include <cstring>
#include <memory>
#include <sys/user.h>

using namespace std::string_view_literals;
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
struct TraceeController;
struct TaskInfo;

class BreakpointLocation;

/// Tracee Control
namespace tc {

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

enum class ReadResult : i8
{
  ERROR = -1,
  EoF = 0,
  OK = 1,
};

struct TraceeReadResult
{
  ReadResult op_result;
  union
  {
    u32 bytes_read;
    i32 sys_errno;
  };

  constexpr bool
  success() const noexcept
  {
    return op_result == ReadResult::OK;
  }

  constexpr static TraceeReadResult
  Ok(u32 bytes_read) noexcept
  {
    return TraceeReadResult{.op_result = ReadResult::OK, .bytes_read = bytes_read};
  }
  constexpr static TraceeReadResult
  Error(int sys_error) noexcept
  {
    return TraceeReadResult{.op_result = ReadResult::ERROR, .sys_errno = sys_error};
  }
  constexpr static TraceeReadResult
  EoF() noexcept
  {
    return TraceeReadResult{.op_result = ReadResult::EoF, .bytes_read = 0};
  }
};

struct PtraceCfg
{
  pid_t tid;
};

struct GdbRemoteCfg
{
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
};

enum class RunType : u8
{
  Step = 0b0001,
  Continue = 0b0010,
  SyscallContinue = 0b0011,
  UNKNOWN = 0b0000,
  None = UNKNOWN
};

std::string_view to_str(RunType type) noexcept;

using InterfaceConfig = std::variant<PtraceCfg, GdbRemoteCfg>;

struct WriteError
{
  AddrPtr address;
  u32 bytes_written;
  int sys_errno;
};

enum DisconnectBehavior
{
  ResumeTarget,
  TerminateTarget
};

// Abstract interface for all tracee communication & command types
// PtraceCommander (a "local" debugging)
// Remote (a remote debug session that functions )
class TraceeCommandInterface
{
public:
  NO_COPY(TraceeCommandInterface);
  TraceeCommandInterface() noexcept = default;
  virtual ~TraceeCommandInterface() noexcept = default;
  virtual TraceeReadResult read_bytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept = 0;
  virtual TraceeWriteResult write_bytes(AddrPtr addr, u8 *buf, u32 size) noexcept = 0;
  // Can (possibly) modify state in `t`
  virtual TaskExecuteResponse resume_task(TaskInfo &t, RunType run) noexcept = 0;
  // Can (possibly) modify state in `t`
  virtual TaskExecuteResponse stop_task(TaskInfo &t) noexcept = 0;

  virtual TaskExecuteResponse enable_breakpoint(BreakpointLocation &location) noexcept = 0;
  virtual TaskExecuteResponse disable_breakpoint(BreakpointLocation &location) noexcept = 0;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  virtual TaskExecuteResponse install_breakpoint(AddrPtr addr) noexcept = 0;

  virtual TaskExecuteResponse read_registers(TaskInfo &t) noexcept = 0;
  virtual TaskExecuteResponse write_registers(const user_regs_struct &input) noexcept = 0;
  virtual TaskExecuteResponse set_pc(const TaskInfo &t, AddrPtr addr) noexcept = 0;
  virtual TaskExecuteResponse disconnect(bool terminate) noexcept = 0;

  virtual bool perform_shutdown() noexcept = 0;
  virtual bool initialize() noexcept = 0;

  virtual bool reconfigure(TraceeController *) noexcept = 0;
  virtual Tid task_leader() const noexcept = 0;

  static std::unique_ptr<TraceeCommandInterface> createCommandInterface(const InterfaceConfig &config) noexcept;

  template <typename T>
  utils::Expected<T, std::string_view>
  read_type(TraceePointer<T> address) noexcept
  {
    typename TPtr<T>::Type t_result;
    auto total_read = 0ull;
    constexpr auto sz = TPtr<T>::type_size();
    const u8 *ptr = static_cast<u8 *>(std::addressof(t_result));
    while (total_read < sz) {
      auto read_result = read_bytes(address, sz - total_read, ptr + total_read);
      switch (read_result.op_result) {
      case ReadResult::ERROR:
        return utils::unexpected(strerror(read_result.sys_errno));
      case ReadResult::EoF:
        return utils::unexpected("End of file reported"sv);
      case ReadResult::OK:
        total_read += read_result.bytes_read;
        if (total_read == sz) {
          return utils::Expected{t_result};
        }
        address += read_result.bytes_read;
        continue;
      }
    }
    return t_result;
  }

  template <typename T>
  utils::Expected<u32, WriteError>
  write(TraceePointer<T> address, const T &value)
  {
    auto total_written = 0ull;
    auto sz = address.type_size();
    const u8 *ptr = static_cast<u8 *>(std::addressof(value));

    while (total_written < sz) {
      const auto written = write_bytes(address + total_written, ptr + total_written, sz - total_written);
      if (written.success) {
        total_written += written.bytes_written;
      } else {
        auto addr_value = reinterpret_cast<std::uintptr_t>(ptr) + total_written;
        return utils::unexpected(WriteError{.address = AddrPtr{addr_value},
                                            .bytes_written = total_written,
                                            .sys_errno = written.err.sys_error_num});
      }
    }
    return {total_written};
  }
};

using Interface = std::unique_ptr<TraceeCommandInterface>;

} // namespace tc