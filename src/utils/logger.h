/** LICENSE TEMPLATE */
#pragma once
#include "common/formatter.h"
#include "tracee_pointer.h"
#include "utils/debugger_thread.h"
#include "utils/dynamic_array.h"
#include "utils/indexing.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <common/macros.h>
#include <common/typedefs.h>
#include <condition_variable>
#include <configuration/command_line.h>
#include <configuration/config.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <unistd.h>
#include <utils/log_channel.h>
#include <utils/scope_defer.h>

template <typename T> concept Formattable = requires(T t) { std::format("{}", t); };

namespace mdb::logging {

template <typename StringType> struct QuoteStringsInList
{
  std::span<const StringType> mStrings;
};
} // namespace mdb::logging

template <typename StringType>
struct std::formatter<mdb::logging::QuoteStringsInList<StringType>>
    : public Default<mdb::logging::QuoteStringsInList<StringType>>
{
  template <typename FormatContext>
  constexpr auto
  format(const mdb::logging::QuoteStringsInList<StringType> &list, FormatContext &ctx) const
  {
    auto it = ctx.out();
    if (list.mStrings.empty()) {
      return it;
    }
    auto span = list.mStrings;
    it = std::format_to(it, R"("{}")", span.front());
    span = span.subspan(1);
    for (const auto &str : span) {
      it = std::format_to(it, R"(,"{}")", str);
    }
    return it;
  }
};

namespace mdb::logging {

struct LogChannel
{
  std::mutex mChannelMutex;
  std::fstream mFileStream;
  void LogMessage(const char *file, u32 line, u32 column, std::string_view message) noexcept;
  void LogMessage(const char *file, u32 line, u32 column, const std::string &message) noexcept;
  void Log(std::string_view msg) noexcept;
};

// TODO: Make this PMR-able
/* Profile event arg. Gets added to the `args` field in a profiling event. All integral values are formatted in
 * hex. */
struct ProfileEventArg
{
  std::string mSerializedArg;

  ProfileEventArg(std::string_view name, AddrPtr address) noexcept;
  ProfileEventArg(std::string_view name, uint64_t value) noexcept;
  ProfileEventArg(std::string_view name, int64_t value) noexcept;
  ProfileEventArg(std::string_view name, std::string_view value) noexcept;
  ProfileEventArg(std::string_view name, const char *value) noexcept;
  ProfileEventArg(std::string_view name, const std::string &value) noexcept;
  ProfileEventArg(std::string_view name, std::span<std::string> args) noexcept;
  ProfileEventArg(std::string_view name, std::span<std::pmr::string> args) noexcept;
  ProfileEventArg(std::string_view name, mdb::Offset offset) noexcept;

  template <typename T>
  ProfileEventArg(std::string_view name, std::span<const T> &listOfFormattableValues) noexcept
    requires(Formattable<T>)
  {
    std::vector<std::string> args;
    args.reserve(listOfFormattableValues.size());
    std::transform(
      listOfFormattableValues.begin(), listOfFormattableValues.end(), std::back_inserter(args), [](auto &&value) {
        return std::format("{}", value);
      });
    mSerializedArg = std::format(R"("{}": [{}])", name, QuoteStringsInList<std::string>{ args });
  }
};

// TODO: Make this PMR-able
struct ProfileEvent
{
  std::string_view mName;
  char mPhase;
  int mTid;
  long long mTimestamp;
  std::string_view mCategory;
  std::vector<ProfileEventArg> mArgs;
};

// TODO: Make this PMR-able
class ProfilingLogger
{
  SessionId mPid;
  bool mClosed{ true };
  bool mShutdown{ false };
  bool mWritten{};
  std::fstream mLogFile;
  std::mutex mEventsMutex{};
  std::condition_variable mNotifySerializerThread{};
  std::unique_ptr<DebuggerThread> mSerializerThread{ nullptr };
  using EventArray = DynArray<ProfileEvent, DynShiftRemovePolicy>;
  EventArray mEvents{};
  // These two containers are swapped out periodically by the profiler thread, which then serializes them to disk.
  EventArray mBufferedForSerialize{};
  static ProfilingLogger *sInstance;

  ProfileEvent *
  GetEvent()
  {
    ProfileEvent *newUninitEvent = nullptr;
    {
      std::lock_guard lock(mEventsMutex);
      if (mEvents.Size() > 100'000 && mBufferedForSerialize.IsEmpty()) {
        SwapBuffers();
      }
      newUninitEvent = mEvents.AddUninit();
    }

    return newUninitEvent;
  }

  void FlushAndClose() noexcept;
  void WriteEvents(EventArray &events) noexcept;

public:
  ~ProfilingLogger() noexcept;

  static void ConfigureProfiling(const Path &path) noexcept;
  static ProfilingLogger *Instance() noexcept;

  void Begin(std::string_view name, std::string_view category, SessionId tid) noexcept;
  void End(std::string_view name, std::string_view category, SessionId tid) noexcept;

  void Begin(std::string_view name, std::string_view category) noexcept;
  void End(std::string_view name, std::string_view category) noexcept;
  void Shutdown() noexcept;
  void SwapBuffers() noexcept;
  void SerializeBuffered() noexcept;

  template <size_t N>
  void
  Begin(std::string_view name, std::string_view category, std::array<ProfileEventArg, N> &&args) noexcept
  {
    if (mShutdown) [[unlikely]] {
      return;
    }
    ProfileEvent *e = GetEvent();
    e->mName = name;
    e->mPhase = 'B';
    e->mTid = gettid();
    e->mTimestamp = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch())
                      .count();
    e->mCategory = category;
    e->mArgs = std::vector<ProfileEventArg>{};
    e->mArgs.reserve(args.size());
    for (auto &&arg : args) {
      e->mArgs.emplace_back(std::move(arg));
    }
  }

  template <size_t N>
  void
  End(std::string_view name, std::string_view category, std::array<ProfileEventArg, N> &&args) noexcept
  {
    if (mShutdown) [[unlikely]] {
      return;
    }
    ProfileEvent *e = GetEvent();
    e->mName = name;
    e->mPhase = 'E';
    e->mTid = gettid();
    e->mTimestamp = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch())
                      .count();
    e->mCategory = category;
    e->mArgs = std::vector<ProfileEventArg>{};
    e->mArgs.reserve(args.size());
    for (auto &&arg : args) {
      e->mArgs.emplace_back(std::move(arg));
    }
  }
};

#define PASTE_HELPER(a, b) a##b
#define PASTE(a, b) PASTE_HELPER(a, b)
#define TOSTRING(a) #a

#if defined(MDB_PROFILE_LOGGER)

#define LOCK_TIME_CONTENTION(result, mutex)                                                                       \
  const auto start = std::chrono::high_resolution_clock::now();                                                   \
  std::lock_guard lock(mutex);                                                                                    \
  const auto result =                                                                                             \
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)      \
      .count();

#define PEARG(name, val) mdb::logging::ProfileEventArg(name, val)

#define PROFILE_BEGIN(name, category) logging::ProfilingLogger::Instance()->Begin(name, category);
#define PROFILE_END(name, category) logging::ProfilingLogger::Instance()->End(name, category);

#define PROFILE_BEGIN_PID(name, category, PID) logging::ProfilingLogger::Instance()->Begin(name, category, PID);
#define PROFILE_END_PID(name, category, PID) logging::ProfilingLogger::Instance()->End(name, category, PID);

#define PROFILE_BEGIN_ARGS(name, category, ...)                                                                   \
  logging::ProfilingLogger::Instance()->Begin(name, category, std::to_array<PEArg>({ __VA_ARGS__ }));

#define PROFILE_END_ARGS(name, category, ...)                                                                     \
  logging::ProfilingLogger::Instance()->End(name, category, std::to_array<PEArg>({ __VA_ARGS__ }));

#define PROFILE_AT_SCOPE_END(name, category, ...)                                                                 \
  ScopedDefer PASTE(endProfileEvent, __LINE__){ [&]() { PROFILE_END_ARGS(name, category, __VA_ARGS__) } };

#define PROFILE_SCOPE_ARGS(name, category, ...)                                                                   \
  PROFILE_BEGIN_ARGS(name, category, __VA_ARGS__)                                                                 \
  ScopedDefer PASTE(                                                                                              \
    endProfileEvent, __LINE__){ [&]() { logging::ProfilingLogger::Instance()->End(name, category); } };

#define PROFILE_SCOPE_END_ARGS(name, category, ...)                                                               \
  PROFILE_BEGIN(name, category)                                                                                   \
  PROFILE_AT_SCOPE_END(name, category, __VA_ARGS__)

#define PROFILE_SCOPE(name, category)                                                                             \
  PROFILE_BEGIN(name, category)                                                                                   \
  ScopedDefer PASTE(                                                                                              \
    endProfileEvent, __LINE__){ [&]() { logging::ProfilingLogger::Instance()->End(name, category); } };

static constexpr auto kInterpreter = "js-interpreter";
static constexpr auto kSymbolication = "symbolication";

#else

#define LOCK_TIME_CONTENTION(result, mutex) std::lock_guard lock(mutex);

#define PEARG(...)
#define PROFILE_BEGIN(...)
#define PROFILE_END(...)
#define PROFILE_BEGIN_PID(...)
#define PROFILE_END_PID(...)
#define PROFILE_BEGIN_ARGS(...)
#define PROFILE_END_ARGS(...)
#define PROFILE_AT_SCOPE_END(...)
#define PROFILE_SCOPE_ARGS(...)
#define PROFILE_SCOPE_END_ARGS(...)
#define PROFILE_SCOPE(...)

#endif

class Logger
{
  static Logger *sLoggerInstance;
  std::atomic<uint64_t> mSequenceId{ 0 };

public:
  Logger() noexcept = default;
  ~Logger() noexcept;
  void SetupChannel(const std::filesystem::path &logDirectory, Channel id) noexcept;
  void Log(Channel id, std::string_view log_msg) noexcept;
  static Logger *GetLogger() noexcept;
  static uint64_t GetLogMessageId() noexcept;

  void OnAbort() noexcept;
  LogChannel *GetLogChannel(Channel id) noexcept;
  void LogMessage() noexcept;

  static void
  LogIf(Channel id, const char *file, u32 line, u32 column, std::string_view message) noexcept
  {
    if (auto *channel = GetLogger()->GetLogChannel(id); channel) {
      channel->LogMessage(file, line, column, message);
    }
  }

  static void
  LogIf(Channel id, std::string_view message) noexcept
  {
    if (auto *channel = GetLogger()->GetLogChannel(id); channel) {
      channel->Log(message);
    }
  }

  static void ConfigureLogging(const mdb::cfg::InitializationConfiguration &config) noexcept;

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
      channel->LogMessage(LOC.file_name(), LOC.line() - 1, LOC.column() - 2, std::format(__VA_ARGS__));           \
    }                                                                                                             \
  }

#define DBGLOG(channel, ...)                                                                                      \
  if (auto channel = mdb::logging::GetLogChannel(Channel::channel); channel) {                                    \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, ::std::format(__VA_ARGS__));  \
  }

#define DBGBUFLOG(channel, ...)                                                                                   \
  if (auto channel = mdb::logging::GetLogChannel(Channel::channel); channel) {                                    \
    std::source_location srcLoc = std::source_location::current();                                                \
    char buf[1024];                                                                                               \
    auto it = ::std::format_to(buf, __VA_ARGS__);                                                                 \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, std::string_view{ buf, it }); \
  }

#define DBGLOG_STR(channel, str)                                                                                  \
  if (auto channel = logging::GetLogChannel(Channel::channel); channel) {                                         \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, str);                         \
  }
#else
#define DLOG(...)
#define DBGLOG(channel, ...)                                                                                      \
  if (auto channel = logging::GetLogChannel(Channel::channel); channel) {                                         \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, ::std::format(__VA_ARGS__));  \
  }

#define DBGBUFLOG(channel, ...)

#define CDLOG(...)
#define DBGLOG_STR(channel, str)                                                                                  \
  if (auto channel = logging::GetLogChannel(Channel::channel); channel) {                                         \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, str);                         \
  }
#endif

} // namespace mdb::logging

using PEArg = mdb::logging::ProfileEventArg;

// Make this the debug formatter in the future.
template <typename T> struct DebugFormatter
{
  bool mDebug{ false };
  BASIC_PARSE
};

template <> struct std::formatter<mdb::Offset> : public Default<mdb::Offset>
{
  template <typename FormatContext>
  constexpr auto
  format(const mdb::Offset &offset, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(), "0x{:x}", offset.value());
  }
};
