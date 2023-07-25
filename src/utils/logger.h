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
  struct LogChannel
  {
    SpinLock spin_lock;
    std::fstream fstream;
    void log(std::string_view msg) noexcept;
  };

  static Logger *logger_instance;

public:
  Logger() noexcept;
  ~Logger() noexcept;
  void setup_channel(std::string_view name) noexcept;
  void log(std::string_view log_name, std::string_view log_msg) noexcept;
  static Logger *get_logger() noexcept;
  void on_abort() noexcept;

private:
  std::unordered_map<std::string_view, LogChannel *> log_files;
};

Logger *get_logging() noexcept;

#ifdef MDB_DEBUG
#define LOG(channel, ...) logging::get_logging()->log(channel, fmt::format(__VA_ARGS__));
#else
#define LOG(channel, ...)
#endif
} // namespace logging
