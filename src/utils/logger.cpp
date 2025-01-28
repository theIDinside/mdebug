/** LICENSE TEMPLATE */
#include "logger.h"
#include "../common.h"
#include "fmt/base.h"
#include "utils/util.h"
#include <ranges>

using namespace std::string_view_literals;

namespace mdb::logging {

logging::Logger *logging::Logger::sLoggerInstance = new logging::Logger{};

Logger::~Logger() noexcept
{
  for (auto ptr : LogChannels) {
    if (ptr) {
      ptr->mFileStream.flush();
      ptr->mFileStream.close();
      delete ptr;
    }
  }
}

void
Logger::SetupChannel(const Path &logDirectory, Channel id) noexcept
{
  ASSERT(LogChannels[std::to_underlying(id)] == nullptr, "Channel {} ({}) already created", 1, id);
  Path p = logDirectory / fmt::format("{}.log", id);
  auto channel =
    new LogChannel{.mChannelMutex = {},
                   .mFileStream = std::fstream{p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc}};
  if (!channel->mFileStream.is_open()) {
    channel->mFileStream.open(p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
  }
  LogChannels[std::to_underlying(id)] = channel;
}

void
Logger::Log(Channel id, std::string_view log_msg) noexcept
{
  if (auto ptr = LogChannels[std::to_underlying(id)]; ptr) {
    ptr->Log(log_msg);
  }
}

Logger *
Logger::GetLogger() noexcept
{
  return Logger::sLoggerInstance;
}

void
Logger::OnAbort() noexcept
{
  for (auto chan : LogChannels | mdb::FilterNullptr()) {
    chan->mFileStream.flush();
    chan->mFileStream.close();
  }
}

void
LogChannel::LogMessage(const char *file, u32 line, u32 column, std::string_view message) noexcept
{
  std::lock_guard guard{mChannelMutex};
  mFileStream << message;
  mFileStream << " [" << file << ":" << line << ":" << column << "]: " << std::endl;
}

void
LogChannel::LogMessage(const char *file, u32 line, u32 column, std::string &&message) noexcept
{
  std::lock_guard guard{mChannelMutex};
  mFileStream << message;
  mFileStream << " [" << file << ":" << line << ":" << column << "]: " << std::endl;
}

void
LogChannel::Log(std::string_view msg) noexcept
{
  std::lock_guard guard{mChannelMutex};
  mFileStream << msg << std::endl;
}

LogChannel *
Logger::GetLogChannel(Channel id) noexcept
{
  return LogChannels[std::to_underlying(id)];
}

Logger *
GetLogger() noexcept
{
  return Logger::GetLogger();
}

LogChannel *
GetLogChannel(Channel id) noexcept
{
  return GetLogger()->GetLogChannel(id);
}

} // namespace mdb::logging