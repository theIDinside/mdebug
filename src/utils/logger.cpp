#include "logger.h"
#include "../common.h"
#include "../lib/lockguard.h"
#include "utils/macros.h"
#include <filesystem>

using namespace std::string_view_literals;

namespace logging {

constexpr std::string_view
to_str(Channel id) noexcept
{
  switch (id) {
  case Channel::core:
    return "core";
  case Channel::dap:
    return "dap";
  case Channel::dwarf:
    return "dwarf";
  case Channel::awaiter:
    return "awaiter";
  case Channel::eh:
    return "eh";
  case Channel::remote:
    return "remote";
  case Channel::COUNT:
    PANIC("Count not a valid Id");
    break;
  }
  MIDAS_UNREACHABLE
}

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

  for (auto ptr : LogChannels) {
    if (ptr) {
      delete ptr;
    }
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
Logger::setup_channel(Channel id) noexcept
{
  ASSERT(LogChannels[std::to_underlying(id)] == nullptr, "Channel {} already created", to_str(id));
  Path p = std::filesystem::current_path() / fmt::format("{}.log", to_str(id));
  auto channel =
    new LogChannel{.spin_lock = SpinLock{},
                   .fstream = std::fstream{p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc}};
  if (!channel->fstream.is_open()) {
    channel->fstream.open(p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
  }
  LogChannels[std::to_underlying(id)] = channel;
}

void
Logger::log(Channel id, std::string_view log_msg) noexcept
{
  if (auto ptr = LogChannels[std::to_underlying(id)]; ptr) {
    ptr->log(log_msg);
  }
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
  if (it != std::end(log_files)) {
    return it->second;
  }
  return nullptr;
}

Logger::LogChannel *
Logger::channel(Channel id)
{
  return LogChannels[std::to_underlying(id)];
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

Logger::LogChannel *
get_log_channel(Channel id) noexcept
{
  return Logger::get_logger()->channel(id);
}

Logger *
get_logging() noexcept
{
  return Logger::get_logger();
}

} // namespace logging