#include "logger.h"
#include "../common.h"
#include "../lib/lockguard.h"
#include <filesystem>
#include <source_location>

using namespace std::string_view_literals;

namespace logging {

logging::Logger *logging::Logger::logger_instance = new logging::Logger{};

Logger::~Logger() noexcept
{
  // Should only happen statically at end of session, so this should be fine.
  for (auto &[n, l] : log_files) {
    if (l->fstream.is_open()) {
      l->fstream.flush();
      l->fstream.close();
    }
    delete l;
  }
}

void
Logger::setup_channel(std::string_view name) noexcept
{
  ASSERT(!log_files.contains(name), "Creating log channel {} twice is not allowed.", name);
  Path p = std::filesystem::current_path() / fmt::format("{}.log", name);
  auto channel =
      new LogChannel{.spin_lock = SpinLock{},
                     .fstream = std::fstream{p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc}};
  if (!channel->fstream.is_open()) {
    channel->fstream.open(p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
  }
  log_files[name] = channel;
}

void
Logger::log(std::string_view log_name, std::string_view log_msg) noexcept
{
  log_files[log_name]->log(log_msg);
}

Logger *
Logger::get_logger() noexcept
{
  return Logger::logger_instance;
}

void
Logger::on_abort() noexcept
{
  for (const auto &[name, channel] : log_files) {
    channel->log_message(std::source_location::current(), "\n - flushed"sv);
    channel->fstream.flush();
  }
}

Logger::LogChannel *
Logger::channel(std::string_view name)
{
  auto it = log_files.find(name);
  if (it != std::end(log_files))
    return it->second;
  return nullptr;
}

void
Logger::LogChannel::log_message(std::source_location loc, std::string_view msg) noexcept
{
  LockGuard<SpinLock> guard{spin_lock};
  fstream << msg;
  fstream << " [" << loc.file_name() << ":" << loc.line() << ":" << loc.column() << "]: " << std::endl;
}

void
Logger::LogChannel::log_message(std::source_location loc, std::string &&msg) noexcept
{
  LockGuard<SpinLock> guard{spin_lock};
  fstream << msg;
  fstream << "\t[" << loc.file_name() << ":" << loc.line() << ":" << loc.column() << "]" << std::endl;
}

void
Logger::LogChannel::log(std::string_view msg) noexcept
{
  LockGuard<SpinLock> guard{spin_lock};
  fstream << msg << std::endl;
}

Logger::LogChannel *
get_log_channel(std::string_view log_channel) noexcept
{
  if (auto logger = Logger::get_logger(); logger) {
    return logger->channel(log_channel);
  }
  return nullptr;
}

Logger *
get_logging() noexcept
{
  return Logger::get_logger();
}

} // namespace logging