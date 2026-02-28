/** MDB Integration with binlog library */
#pragma once

#if defined(MDB_BINARY_LOGGING)

#include <binlog/logger.h>
#include <configuration/config.h>
#include <memory>
#include <utils/log_channel.h>
#include <utils/log_format_map.h>

namespace mdb::logging {

/**
 * Global binary logger instance for MDB.
 * Initialized by ConfigureLogging().
 */
inline std::unique_ptr<binlog::BinaryLogger> gBinaryLogger = nullptr;

/**
 * Initialize binary logging for MDB.
 * Called from Logger::ConfigureLogging().
 */
inline void
InitializeBinaryLogging(const cfg::InitializationConfiguration &config)
{
  binlog::BinaryLogger::Config binlogConfig{ .logFilePath = config.mLogDirectory / "mdb.binlog" };

  gBinaryLogger = std::make_unique<binlog::BinaryLogger>(binlogConfig);
}

/**
 * Get the binary logger instance.
 */
inline binlog::BinaryLogger *
GetBinaryLogger() noexcept
{
  return gBinaryLogger.get();
}

/**
 * Shutdown binary logging.
 */
inline void
ShutdownBinaryLogging() noexcept
{
  if (gBinaryLogger) {
    gBinaryLogger->Shutdown();
    gBinaryLogger.reset();
  }
}

} // namespace mdb::logging

/**
 * Binary logging macro for MDB.
 * Automatically looks up format ID at compile time.
 */
#define BINLOG(channel, format_str, ...)                                                                          \
  do {                                                                                                            \
    if (auto *logger = ::mdb::logging::GetBinaryLogger(); logger) [[likely]] {                                    \
      constexpr ::binlog::u32 fmtHash = ::mdb::logging::detail::HashFormatString(format_str);                     \
      constexpr ::binlog::u32 fmtId = ::mdb::logging::detail::GetFormatId(fmtHash);                               \
      logger->Log(static_cast<::binlog::u8>(static_cast<std::underlying_type_t<Channel>>(Channel::channel)),      \
        fmtId,                                                                                                    \
        std::source_location::current() __VA_OPT__(, ) __VA_ARGS__);                                              \
    }                                                                                                             \
  } while (false)

#endif // MDB_BINARY_LOGGING
