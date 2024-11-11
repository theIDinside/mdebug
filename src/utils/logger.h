#pragma once
#include "../lib/spinlock.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include <array>
#include <fstream>
#include <memory>
#include <source_location>
#include <string>
#include <typedefs.h>
#include <unordered_map>
#include <utility>

namespace logging {

enum class Channel : u32
{
  core = 0,
  // Debug Adapter Protocol
  dap,
  // Debug Symbol Information
  dwarf,
  // Awaiter thread
  awaiter,
  // Exception frame headers
  eh,
  // Gdb Remote Protocol
  remote,

  // Keep always last. Always.
  COUNT
};

consteval std::array<Channel, std::to_underlying(Channel::COUNT)>
DefaultChannels()
{
  std::array<Channel, std::to_underlying(Channel::COUNT)> res{};
  for (auto i = u32{0}; i < std::to_underlying(Channel::COUNT); ++i) {
    res[i] = static_cast<Channel>(i);
  }
  return res;
}

constexpr std::string_view to_str(Channel id) noexcept;

class Logger
{
  static Logger *logger_instance;

public:
  struct LogChannel
  {
    SpinLock spin_lock;
    std::fstream fstream;
    void log_message(std::source_location loc, std::string_view msg) noexcept;
    void log_message(std::source_location loc, std::string &&msg) noexcept;
    void log(std::string_view msg) noexcept;
  };

  Logger() noexcept = default;
  ~Logger() noexcept;
  void setup_channel(std::string_view name) noexcept;
  void setup_channel(Channel id) noexcept;
  void log(std::string_view log_name, std::string_view log_msg) noexcept;
  void log(Channel id, std::string_view log_msg) noexcept;
  static Logger *get_logger() noexcept;
  void on_abort() noexcept;
  LogChannel *channel(std::string_view name);
  LogChannel *channel(Channel id);

private:
  std::unordered_map<std::string_view, LogChannel *> log_files{};
  std::array<LogChannel *, std::to_underlying(Channel::COUNT)> LogChannels{};
};

Logger *get_logging() noexcept;
Logger::LogChannel *get_log_channel(std::string_view log_channel) noexcept;
Logger::LogChannel *get_log_channel(Channel id) noexcept;

// clang-format off
#if defined(MDB_DEBUG) and MDB_DEBUG == 1

// CONDITIONAL DEBUG LOG
#define CDLOG(condition, channel_name, ...) if((condition)) { auto LOC = std::source_location::current();         \
    if (auto channel = logging::get_log_channel(logging::Channel::channel_name); channel) {                       \
      channel->log_message(LOC, fmt::format(__VA_ARGS__));                                                        \
    }                                                                                                             \
  }

// DEBUG LOG - Gets removed in release builds
#define DLOG(channel_name, ...)  {std::source_location SOURCE_LOC__ = std::source_location::current();            \
  if (auto channel = logging::get_log_channel(channel_name); channel) {                                           \
    channel->log_message(SOURCE_LOC__, fmt::format(__VA_ARGS__));                                                 \
  }}

#define DBGLOG(channel, ...) {std::source_location SOURCE_LOC__ = std::source_location::current();                \
  if (auto channel = logging::get_log_channel(logging::Channel::channel); channel) {                              \
    channel->log_message(SOURCE_LOC__, fmt::format(__VA_ARGS__));                                                 \
  }}
#else
#define DLOG(...)
#define DBGLOG(...)
#define CDLOG(...)
#endif

#define LOG(channel, ...) logging::get_logging()->log(logging::Channel::channel, fmt::format(__VA_ARGS__));

// clang-format on

} // namespace logging

using LogChannel = logging::Channel;

template <typename... Ts>
void
debug_log(LogChannel id, const std::source_location &loc, std::string_view fmt_str, Ts... ts)
{
  if (auto channel = logging::get_log_channel(id); channel != nullptr) {
    channel->log_message(loc, fmt::format(fmt_str, ts...));
  }
}

#define DebugLog(id, FormatString, ...) debug_log(id, std::source_location::current(), FormatString, __VA_ARGS__);
