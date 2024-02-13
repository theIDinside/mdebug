#pragma once
#include "../lib/spinlock.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>

namespace logging {
class Logger
{
  static Logger *logger_instance;

public:
  struct LogChannel
  {
    SpinLock spin_lock;
    std::fstream fstream;
    void log(std::string_view msg) noexcept;
    void log(std::string &&msg) noexcept;
  };

  Logger() noexcept;
  ~Logger() noexcept;
  void setup_channel(std::string_view name) noexcept;
  void log(std::string_view log_name, std::string_view log_msg) noexcept;
  static Logger *get_logger() noexcept;
  void on_abort() noexcept;
  LogChannel *channel(std::string_view name);

private:
  std::unordered_map<std::string_view, LogChannel *> log_files;
};

Logger *get_logging() noexcept;
Logger::LogChannel *get_log_channel(std::string_view log_channel) noexcept;

#if defined(MDB_DEBUG) and MDB_DEBUG == 1
#define DLOG(channel_name, ...)                                                                                   \
  if (auto channel = logging::get_log_channel(channel_name); channel) {                                           \
    channel->log(fmt::format(__VA_ARGS__));                                                                       \
  }
#else
#define DLOG(channel, ...)
#endif

#define LOG(channel, ...) logging::get_logging()->log(channel, fmt::format(__VA_ARGS__));

} // namespace logging
