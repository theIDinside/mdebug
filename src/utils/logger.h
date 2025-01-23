/** LICENSE TEMPLATE */
#pragma once
#include "fmt/core.h"
#include "fmt/format.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <source_location>
#include <string>
#include <typedefs.h>
#include <unordered_map>

namespace logging {

enum class Channel : u32
{
#define DEFINE_CHANNEL(chan, name, desc) chan,
#include <defs/log_channels.defs>
#undef DEFINE_CHANNEL
};

constexpr static auto LogChannelNames = std::to_array({
#define DEFINE_CHANNEL(chan, name, desc) name,
#include <defs/log_channels.defs>
#undef DEFINE_CHANNEL
});

consteval static auto
ChannelCount() noexcept
{
  return std::size(LogChannelNames);
}

consteval std::array<Channel, ChannelCount()>
DefaultChannels()
{
  std::array<Channel, ChannelCount()> res{};
  for (auto i = u32{0}; i < ChannelCount(); ++i) {
    res[i] = static_cast<Channel>(i);
  }
  return res;
}

class Logger
{
  static Logger *sLoggerInstance;

public:
  struct LogChannel
  {
    std::mutex mChannelMutex;
    std::fstream mFileStream;
    void LogMessage(const char *file, u32 line, u32 column, std::string_view message) noexcept;
    void LogMessage(const char *file, u32 line, u32 column, std::string &&message) noexcept;
    void Log(std::string_view msg) noexcept;
  };

  Logger() noexcept = default;
  ~Logger() noexcept;
  void SetupChannel(const std::filesystem::path &logDirectory, Channel id) noexcept;
  void Log(Channel id, std::string_view log_msg) noexcept;
  static Logger *GetLogger() noexcept;
  void OnAbort() noexcept;
  LogChannel *GetChannel(Channel id);

private:
  std::array<LogChannel *, ChannelCount()> LogChannels{};
};

Logger *GetLogger() noexcept;
Logger::LogChannel *GetLogChannel(Channel id) noexcept;

#if defined(MDB_DEBUG) and MDB_DEBUG == 1

// CONDITIONAL DEBUG LOG
#define CDLOG(condition, channel_name, ...)                                                                       \
  if ((condition)) {                                                                                              \
    auto LOC = std::source_location::current();                                                                   \
    if (auto channel = logging::GetLogChannel(logging::Channel::channel_name); channel) {                         \
      channel->LogMessage(LOC.file_name(), LOC.line() - 1, LOC.column() - 2, fmt::format(__VA_ARGS__));           \
    }                                                                                                             \
  }

#define DBGLOG(channel, ...)                                                                                      \
  if (auto channel = logging::GetLogChannel(logging::Channel::channel); channel) {                                \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, fmt::format(__VA_ARGS__));    \
  }
#else
#define DLOG(...)
#define DBGLOG(...)
#define CDLOG(...)
#endif

} // namespace logging

using LogChannel = logging::Channel;

template <typename... Ts>
void
debug_log(LogChannel id, const std::source_location &loc, std::string_view fmt_str, Ts... ts)
{
  if (auto channel = logging::GetLogChannel(id); channel != nullptr) {
    channel->LogMessage(loc, fmt::format(fmt_str, ts...));
  }
}

#define DebugLog(id, FormatString, ...) debug_log(id, std::source_location::current(), FormatString, __VA_ARGS__);

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

template <> struct formatter<logging::Channel> : DebugFormatter<logging::Channel>
{

  template <typename FormatContext>
  auto
  format(const logging::Channel &channel, FormatContext &ctx) const
  {
#define DEFINE_CHANNEL(chan, name, desc)                                                                          \
  case logging::Channel::chan:                                                                                    \
    if (mDebug) {                                                                                                 \
      return fmt::format_to(ctx.out(), name);                                                                     \
    } else {                                                                                                      \
      return fmt::format_to(ctx.out(), #chan);                                                                    \
    }
    switch (channel) {
#include <defs/log_channels.defs>
    }
#undef DEFINE_CHANNEL
  }
};
} // namespace fmt