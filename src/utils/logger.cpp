/** LICENSE TEMPLATE */
#include "logger.h"
#include "../common.h"
#include "utils/util.h"
#include <algorithm>
#include <configuration/command_line.h>
#include <filesystem>
#include <ranges>

using namespace std::string_view_literals;

namespace mdb::logging {

static void
SerializeEvent(SessionId processId, std::ostream &out, const ProfileEvent &evt) noexcept
{
  out << "{" << R"("name":")" << evt.mName << R"(", "cat":")" << evt.mCategory << R"(", "ph":")" << evt.mPhase
      << R"(", "ts":)" << evt.mTimestamp << R"(, "pid":)" << processId << R"(, "tid":)" << evt.mTid;
  if (!evt.mArgs.empty()) {
    out << R"(, "args":{ )" << evt.mArgs[0].mSerializedArg;
    for (const auto &arg : std::span{ evt.mArgs }.subspan(1)) {
      out << "," << arg.mSerializedArg;
    }
    out << "}";
  }
  out << "}";
}

logging::Logger *logging::Logger::sLoggerInstance = new logging::Logger{};
logging::ProfilingLogger *logging::ProfilingLogger::sInstance = nullptr;

ProfileEventArg::ProfileEventArg(std::string_view name, AddrPtr address) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, address);
}

ProfileEventArg::ProfileEventArg(std::string_view name, uint64_t value) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, int64_t value) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, const std::string &value) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, std::string_view value) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, const char *value) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, value);
}

ProfileEventArg::ProfileEventArg(std::string_view name, std::span<std::string> args) noexcept
{
  mSerializedArg = std::format(R"("{}": [{}])", name, logging::QuoteStringsInList<std::string>{ args });
}

ProfileEventArg::ProfileEventArg(std::string_view name, std::span<std::pmr::string> args) noexcept
{
  mSerializedArg = std::format(R"("{}": [{}])", name, logging::QuoteStringsInList<std::pmr::string>{ args });
}

ProfileEventArg::ProfileEventArg(std::string_view name, mdb::Offset offset) noexcept
{
  mSerializedArg = std::format(R"("{}":"{}")", name, offset);
}

void
ProfilingLogger::FlushAndClose() noexcept
{
  DBGLOG(core, "Profiling logger shutting down with flush & close.");
  if (!mBufferedForSerialize.IsEmpty()) {
    WriteEvents(mBufferedForSerialize);
  }
  if (!mEvents.IsEmpty()) {
    WriteEvents(mEvents);
  }
  mLogFile << "\n]\n}\n";
  mLogFile.flush();
  mLogFile.close();
}

void
ProfilingLogger::WriteEvents(EventArray &events) noexcept
{
  std::span<const ProfileEvent> span = events.Span();
  if (events.IsEmpty()) {
    return;
  }

  if (!mWritten) {
    SerializeEvent(mPid, mLogFile, span.front());
    span = span.subspan(1);
  }

  for (const auto &evt : span) {
    mLogFile << ",\n";
    SerializeEvent(mPid, mLogFile, evt);
  }
  mWritten = true;
  mLogFile.flush();
  events.Clear();
}

/* static */
void
ProfilingLogger::ConfigureProfiling(const Path &path) noexcept
{
  MDB_ASSERT(!sInstance, "Profiler already instantiated.");
  sInstance = new logging::ProfilingLogger{};
  const auto profilingFile = path / "profiling.log";
  sInstance->mPid = getpid();
  sInstance->mLogFile =
    std::fstream{ profilingFile, std::ios_base::in | std::ios_base::out | std::ios_base::trunc };
  sInstance->mLogFile << "{\n" << R"("displayTimeUnit": "ns", "traceEvents": [)" << '\n';
  sInstance->mClosed = false;
  sInstance->mEvents.Reserve(512 * 512);
  sInstance->mBufferedForSerialize.Reserve(512 * 512);
  sInstance->mSerializerThread = DebuggerThread::SpawnDebuggerThread("Profiler", [&](std::stop_token &token) {
    while (!token.stop_requested()) {
      {
        std::unique_lock lock(sInstance->mEventsMutex);
        sInstance->mNotifySerializerThread.wait(lock);
      }
      sInstance->SerializeBuffered();
    }
    sInstance->FlushAndClose();
  });
}

void
ProfilingLogger::SwapBuffers() noexcept
{
  decltype(mEvents)::Swap(mEvents, mBufferedForSerialize);
  mNotifySerializerThread.notify_all();
}

void
ProfilingLogger::SerializeBuffered() noexcept
{
  DBGLOG(core, "Writing {} profiling events", mBufferedForSerialize.Size());
  WriteEvents(mBufferedForSerialize);
}

void
ProfilingLogger::Shutdown() noexcept
{
  if (!mShutdown) {
    mShutdown = true;
    mSerializerThread->RequestStop();
    // in case we're stopped at the cv, tell it to wake up.
    mNotifySerializerThread.notify_all();
    DBGLOG(core, "Awaiting join for profiler task");
    mSerializerThread->Join();
  }
}

/* static */
ProfilingLogger *
ProfilingLogger::Instance() noexcept
{
  return sInstance;
}

void
ProfilingLogger::Begin(std::string_view name, std::string_view category, SessionId tid) noexcept
{
  if (mShutdown) [[unlikely]] {
    return;
  }
  ProfileEvent *e = GetEvent();
  e->mName = name;
  e->mPhase = 'B';
  e->mTid = tid;
  e->mTimestamp = std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::high_resolution_clock::now().time_since_epoch())
                    .count();
  e->mArgs = {};
  e->mCategory = category;
}

void
ProfilingLogger::End(std::string_view name, std::string_view category, SessionId tid) noexcept
{
  if (mShutdown) [[unlikely]] {
    return;
  }
  ProfileEvent *e = GetEvent();
  e->mName = name;
  e->mPhase = 'E';
  e->mTid = tid;
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

/* static */
void
Logger::ConfigureLogging(const mdb::cfg::InitializationConfiguration &config) noexcept
{
  // TODO(simon): Make this configurable (again). It was just too big of a pain during testing, so I just enabled
  // all log channels. Need to integrate this into the test suite as well as the vscode extension so that
  // environment variables are properly set.
  const auto &channels = config.mLogChannels;
  DBGLOG(core, "channels set: {}", channels.size());
  for (auto channel : Enum<Channel>::Variants()) {
    sLoggerInstance->SetupChannel(config.mLogDirectory, channel);
  }

  ProfilingLogger::ConfigureProfiling(config.mLogDirectory);
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
  MDB_ASSERT(LogChannels[std::to_underlying(id)] == nullptr, "Channel {} ({}) already created", 1, id);
  Path p = logDirectory / std::format("{}.log", id);
  auto channel = new LogChannel{ .mChannelMutex = {},
    .mFileStream = std::fstream{ p, std::ios_base::in | std::ios_base::out | std::ios_base::trunc } };
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

/* static */
uint64_t
Logger::GetLogMessageId() noexcept
{
  return (*GetLogger()).mSequenceId++;
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
  std::lock_guard guard{ mChannelMutex };
  const auto id = Logger::GetLogMessageId();
  mFileStream << '[' << id << "] " << message;
  char buf[1024];
  auto it = std::format_to(buf, " [{}:{}]", file, line);
  *it = 0;
  mFileStream << buf << std::endl;
}

void
LogChannel::LogMessage(const char *file, u32 line, u32 column, const std::string &message) noexcept
{
  LogMessage(file, line, column, std::string_view{ message });
}

void
LogChannel::Log(std::string_view msg) noexcept
{
  std::lock_guard guard{ mChannelMutex };
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