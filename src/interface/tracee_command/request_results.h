/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <utils/byte_buffer.h>
#include <utils/immutable.h>
// std
#include <optional>

namespace mdb::tc {
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

enum class ApplicationError : u8
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

enum class TaskExecuteResult : u8
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

struct Error
{
  Immutable<std::optional<int>> mSysErrorNumber;
  Immutable<std::string_view> mErrorMessage;
  Immutable<std::optional<std::string>> mError{};
};

struct NonFullRead
{
  std::unique_ptr<ByteBuffer> mBytes;
  u32 mUnreadBytes;
  int mErrorNumber;
};
} // namespace mdb::tc