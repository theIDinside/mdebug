/** LICENSE TEMPLATE */
#include "logger.h"
#include "../common.h"
#include "fmt/base.h"
#include "lib/arena_allocator.h"
#include "utils/util.h"
#include <algorithm>
#include <ranges>

using namespace std::string_view_literals;

namespace mdb::logging {

logging::Logger *logging::Logger::sLoggerInstance = new logging::Logger{};
logging::ProfilingLogger *logging::ProfilingLogger::sInstance = nullptr;

ProfileEventArg::ProfileEventArg(std::string_view name, AddrPtr address) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, address);
}

ProfileEventArg::ProfileEventArg(std::string_view name, uint64_t value) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, int64_t value) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, const std::string &value) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, std::string_view value) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, const char *value) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, std::span<std::string> args) noexcept
{
  mSerializedArg = fmt::format(R"("{}": [{}])", name, logging::QuoteStringsInList{args});
}

ProfileEventArg::ProfileEventArg(std::string_view name, mdb::Offset offset) noexcept
{
  mSerializedArg = fmt::format(R"("{}":"{}")", name, offset);
}

/* static */
void
ProfilingLogger::ConfigureProfiling(const Path &path) noexcept
{
  ASSERT(!sInstance, "Profiler already instantiated.");
  sInstance = new logging::ProfilingLogger{};
  const auto profilingFile = path / "profiling.log";
  sInstance->mPid = getpid();
  sInstance->mLogFile = std::fstream{profilingFile, std::ios_base::in | std::ios_base::out | std::ios_base::trunc};
  sInstance->mLogFile << "{\n" << R"("displayTimeUnit": "ns", "traceEvents": [)" << '\n';
  sInstance->mClosed = false;
  sInstance->mEvents.Reserve(1024 * 1024);
  atexit([]() { delete ProfilingLogger::sInstance; });
}

ProfilingLogger::~ProfilingLogger() noexcept
{
  WriteEvents();
  if (!mClosed && mLogFile.is_open()) {
    mLogFile << "\n]\n}\n";
  }
  mLogFile.close();
}

/* static */
ProfilingLogger *
ProfilingLogger::Instance() noexcept
{
  return sInstance;
}

void
ProfilingLogger::Begin(std::string_view name, std::string_view category, Pid pid) noexcept
{
  ProfileEvent *e = GetEvent();
  e->mName = name;
  e->mPhase = 'B';
  e->mTid = pid;
  e->mTimestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::high_resolution_clock::now().time_since_epoch())
                    .count();
  e->mArgs = {};
  e->mCategory = category;
}
void
ProfilingLogger::End(std::string_view name, std::string_view category, Pid pid) noexcept
{
  ProfileEvent *e = GetEvent();
  e->mName = name;
  e->mPhase = 'E';
  e->mTid = pid;
  e->mTimestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::high_resolution_clock::now().time_since_epoch())
                    .count();
  e->mArgs = {};
  e->mCategory = category;
}

void
ProfilingLogger::Begin(std::string_view name, std::string_view category) noexcept
{
  Begin(name, category, gettid());
}

void
ProfilingLogger::End(std::string_view name, std::string_view category) noexcept
{
  End(name, category, gettid());
}

static void
SerializeEvent(Pid processId, std::ostream &out, const ProfileEvent &evt) noexcept
{
  out << "{" << R"("name":")" << evt.mName << R"(", "cat":")" << evt.mCategory << R"(", "ph":")" << evt.mPhase
      << R"(", "ts":)" << evt.mTimestamp << R"(, "pid":)" << processId << R"(, "tid":)" << evt.mTid;
  if (!evt.mArgs.empty()) {
    out << R"(, "args":{ )" << evt.mArgs[0].mSerializedArg;
    for (const auto &arg : std::span{evt.mArgs}.subspan(1)) {
      out << "," << arg.mSerializedArg;
    }
    out << "}";
  }
  out << "}";
}

void
ProfilingLogger::WriteEvents() noexcept
{
  std::lock_guard lock(mEventsMutex);
  if (mWritten) {
    return;
  }
  if (mEvents.IsEmpty()) {
    return;
  }
  std::span<const ProfileEvent> events = mEvents.Span();

  SerializeEvent(mPid, mLogFile, events.front());
  events = events.subspan(1);
  for (const auto &evt : events) {
    mLogFile << ",\n";
    SerializeEvent(mPid, mLogFile, evt);
  }
  mWritten = true;
  mLogFile.flush();
}

/* static */
void
Logger::ConfigureLogging(const Path &logDirectory, const char *logEnvironVariable) noexcept
{
  std::string_view variables{logEnvironVariable};
  std::vector<std::string_view> logList = SplitString(variables, ",");
  static constexpr auto LogModuleNames = Enum<Channel>::Names();

  if (std::ranges::any_of(logList, [](std::string_view cfg) { return cfg.contains("all"); })) {
    auto channels = Enum<Channel>::Variants();
    for (auto channel : channels) {
      sLoggerInstance->SetupChannel(logDirectory, channel);
    }
    return;
  }

  for (auto logModuleName : logList) {
    if (auto it = std::find(LogModuleNames.begin(), LogModuleNames.end(), logModuleName);
        it != std::end(LogModuleNames)) {
      auto logChannel = Enum<Channel>::FromInt(std::distance(it, std::end(LogModuleNames)));
      if (logChannel) {
        sLoggerInstance->SetupChannel(logDirectory, *logChannel);
      }
    }
  }
}

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