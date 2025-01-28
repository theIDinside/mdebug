/** LICENSE TEMPLATE */
#pragma once
#include "fmt/core.h"
#include "utils/macros.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <typedefs.h>

#define FOR_EACH_LOG(LOGCHANNEL)                                                                                  \
  LOGCHANNEL(core, "Debugger Core", "Messages that don't have a intuitive log channel can be logged here.")       \
  LOGCHANNEL(dap, "Debug Adapter Protocol", "Log messages involving the DA protocol should be logged here.")      \
  LOGCHANNEL(dwarf, "DWARF Debug Symbol Information",                                                             \
             "Log messages involving symbol parsing and value evaluation")                                        \
  LOGCHANNEL(awaiter, "Wait Status Reading",                                                                      \
             "Log messages involving the wait status or wait-status adjacent systems")                            \
  LOGCHANNEL(eh, "Exception Frame Header",                                                                        \
             "Log messages that involve unwinding and parsing unwind symbol information")                         \
  LOGCHANNEL(remote, "GDB Remote Protocol", "Log messages related to the GDB Remote Protocol")                    \
  LOGCHANNEL(perf, "Performance Timing & Measuring",                                                              \
             "If you wrap computationally heavy operations in high resolution clock timing, log those messages "  \
             "to this channel")                                                                                   \
  LOGCHANNEL(warning, "Warnings", "Unexpected behaviors should be logged to this chanel")                         \
  LOGCHANNEL(interpreter, "Debugger script interpreter", "Log interpreter related messages here")

ENUM_TYPE_METADATA(Channel, FOR_EACH_LOG, DEFAULT_ENUM)

namespace mdb::logging {

struct LogChannel
{
  std::mutex mChannelMutex;
  std::fstream mFileStream;
  void LogMessage(const char *file, u32 line, u32 column, std::string_view message) noexcept;
  void LogMessage(const char *file, u32 line, u32 column, std::string &&message) noexcept;
  void Log(std::string_view msg) noexcept;
};

class Logger
{
  static Logger *sLoggerInstance;

public:
  Logger() noexcept = default;
  ~Logger() noexcept;
  void SetupChannel(const std::filesystem::path &logDirectory, Channel id) noexcept;
  void Log(Channel id, std::string_view log_msg) noexcept;
  static Logger *GetLogger() noexcept;
  void OnAbort() noexcept;
  LogChannel *GetLogChannel(Channel id) noexcept;

private:
  std::array<LogChannel *, Enum<Channel>::Count()> LogChannels{};
};

Logger *GetLogger() noexcept;
LogChannel *GetLogChannel(Channel id) noexcept;

#if defined(MDB_DEBUG) and MDB_DEBUG == 1

// CONDITIONAL DEBUG LOG
#define CDLOG(condition, channel_name, ...)                                                                       \
  if ((condition)) {                                                                                              \
    auto LOC = std::source_location::current();                                                                   \
    if (auto channel = logging::GetLogChannel(Channel::channel_name); channel) {                                  \
      channel->LogMessage(LOC.file_name(), LOC.line() - 1, LOC.column() - 2, fmt::format(__VA_ARGS__));           \
    }                                                                                                             \
  }

#define DBGLOG(channel, ...)                                                                                      \
  if (auto channel = logging::GetLogChannel(Channel::channel); channel) {                                         \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, ::fmt::format(__VA_ARGS__));  \
  }
#else
#define DLOG(...)
#define DBGLOG(...)
#define CDLOG(...)
#endif

} // namespace mdb::logging

namespace fmt {

// Make this the debug formatter in the future.
template <typename T> struct DebugFormatter
{
  bool mDebug{false};
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &context)
  {
    return context.begin();
  }
};
} // namespace fmt