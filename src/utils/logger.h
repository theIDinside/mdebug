/** LICENSE TEMPLATE */
#pragma once
#include "fmt/core.h"
#include "lib/arena_allocator.h"
#include "tracee_pointer.h"
#include "utils/dynamic_array.h"
#include "utils/indexing.h"
#include "utils/macros.h"
#include "utils/scope_defer.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <typedefs.h>
#include <unistd.h>

#define FOR_EACH_LOG(LOGCHANNEL)                                                                                  \
  LOGCHANNEL(core, "Debugger Core", "Messages that don't have a intuitive log channel can be logged here.")       \
  LOGCHANNEL(dap, "Debug Adapter Protocol", "Log messages involving the DA protocol should be logged here.")      \
  LOGCHANNEL(dwarf, "DWARF Debug Symbol Information",                                                             \
             "Log messages involving symbol parsing and value evaluation")                                        \
  LOGCHANNEL(awaiter, "Wait Status Reading",                                                                      \
             "Log messages involving the wait status or wait-status adjacent systems")                            \
  LOGCHANNEL(eh, "Exception Frame Header",                                                                        \
             "Log messages that involve unwinding and parsing unwind symbol information")                         \
  LOGCHANNEL(remote, "GDB Remote Protocol", "Log messages related to the GDB Remote Protocol")                    \
  LOGCHANNEL(warning, "Warnings", "Unexpected behaviors should be logged to this chanel")                         \
  LOGCHANNEL(interpreter, "Debugger script interpreter", "Log interpreter related messages here")

ENUM_TYPE_METADATA(Channel, FOR_EACH_LOG, DEFAULT_ENUM)

template <typename T> concept Formattable = requires(T t) { fmt::format("{}", t); };

namespace mdb::logging {
struct QuoteStringsInList
{
  std::span<const std::string> mStrings;
};
} // namespace mdb::logging

namespace fmt {
template <> struct formatter<mdb::logging::QuoteStringsInList> : public Default<mdb::logging::QuoteStringsInList>
{
  template <typename FormatContext>
  constexpr auto
  format(const mdb::logging::QuoteStringsInList &list, FormatContext &ctx) const
  {
    auto it = ctx.out();
    if (list.mStrings.empty()) {
      return it;
    }
    auto span = list.mStrings;
    it = fmt::format_to(it, R"("{}")", span.front());
    span = span.subspan(1);
    for (const auto &str : span) {
      it = fmt::format_to(it, R"(,"{}")", str);
    }
    return it;
  }
};
} // namespace fmt

namespace mdb::logging {

struct LogChannel
{
  std::mutex mChannelMutex;
  std::fstream mFileStream;
  void LogMessage(const char *file, u32 line, u32 column, std::string_view message) noexcept;
  void LogMessage(const char *file, u32 line, u32 column, std::string &&message) noexcept;
  void Log(std::string_view msg) noexcept;
};

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
  ProfileEventArg(std::string_view name, mdb::Offset offset) noexcept;

  template <typename T>
  ProfileEventArg(std::string_view name, std::span<const T> &listOfFormattableValues) noexcept
    requires(Formattable<T>)
  {
    std::vector<std::string> args;
    args.reserve(listOfFormattableValues.size());
    std::transform(listOfFormattableValues.begin(), listOfFormattableValues.end(), std::back_inserter(args),
                   [](auto &&value) { return fmt::format("{}", value); });
    mSerializedArg = fmt::format(R"("{}": [{}])", name, QuoteStringsInList{args});
  }
};

struct ProfileEvent
{
  std::string_view mName;
  char mPhase;
  int mTid;
  long long mTimestamp;
  std::string_view mCategory;
  std::vector<ProfileEventArg> mArgs;
};

class ProfilingLogger
{
  Pid mPid;
  bool mClosed{true};
  bool mWritten{};
  std::fstream mLogFile;
  std::mutex mEventsMutex{};
  DynArray<ProfileEvent, DynShiftRemovePolicy> mEvents;

  static ProfilingLogger *sInstance;

  ProfileEvent *
  GetEvent()
  {
    std::lock_guard lock(mEventsMutex);
    return mEvents.AddUninit();
  }

public:
  ~ProfilingLogger() noexcept;

  static void ConfigureProfiling(const Path &path) noexcept;
  static ProfilingLogger *Instance() noexcept;

  void Begin(std::string_view name, std::string_view category, Pid pid) noexcept;
  void End(std::string_view name, std::string_view category, Pid pid) noexcept;

  void Begin(std::string_view name, std::string_view category) noexcept;
  void End(std::string_view name, std::string_view category) noexcept;

  template <size_t N>
  void
  Begin(std::string_view name, std::string_view category, std::array<ProfileEventArg, N> &&args) noexcept
  {
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

  void WriteEvents() noexcept;
};

#define PASTE_HELPER(a, b) a##b
#define PASTE(a, b) PASTE_HELPER(a, b)
#define TOSTRING(a) #a

#if defined(MDB_PROFILE_LOGGER)

#define PEARG(name, val) mdb::logging::ProfileEventArg(name, val)

#define PROFILE_BEGIN(name, category) logging::ProfilingLogger::Instance()->Begin(name, category);
#define PROFILE_END(name, category) logging::ProfilingLogger::Instance()->End(name, category);

#define PROFILE_BEGIN_PID(name, category, PID) logging::ProfilingLogger::Instance()->Begin(name, category, PID);
#define PROFILE_END_PID(name, category, PID) logging::ProfilingLogger::Instance()->End(name, category, PID);

#define PROFILE_BEGIN_ARGS(name, category, ...)                                                                   \
  logging::ProfilingLogger::Instance()->Begin(name, category, std::to_array<PEArg>({__VA_ARGS__}));

#define PROFILE_END_ARGS(name, category, ...)                                                                     \
  logging::ProfilingLogger::Instance()->End(name, category, std::to_array<PEArg>({__VA_ARGS__}));

#define PROFILE_AT_SCOPE_END(name, category, ...)                                                                 \
  ScopedDefer PASTE(endProfileEvent, __LINE__){[&]() { PROFILE_END_ARGS(name, category, __VA_ARGS__) }};

#define PROFILE_SCOPE_ARGS(name, category, ...)                                                                   \
  PROFILE_BEGIN_ARGS(name, category, __VA_ARGS__)                                                                 \
  ScopedDefer PASTE(endProfileEvent,                                                                              \
                    __LINE__){[&]() { logging::ProfilingLogger::Instance()->End(name, category); }};

#define PROFILE_SCOPE_END_ARGS(name, category, ...)                                                               \
  PROFILE_BEGIN(name, category)                                                                                   \
  PROFILE_AT_SCOPE_END(name, category, __VA_ARGS__)

#define PROFILE_SCOPE(name, category)                                                                             \
  PROFILE_BEGIN(name, category)                                                                                   \
  ScopedDefer PASTE(endProfileEvent,                                                                              \
                    __LINE__){[&]() { logging::ProfilingLogger::Instance()->End(name, category); }};

#else

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

public:
  Logger() noexcept = default;
  ~Logger() noexcept;
  void SetupChannel(const std::filesystem::path &logDirectory, Channel id) noexcept;
  void Log(Channel id, std::string_view log_msg) noexcept;
  static Logger *GetLogger() noexcept;
  void OnAbort() noexcept;
  LogChannel *GetLogChannel(Channel id) noexcept;

  static void ConfigureLogging(const Path &logDirectory, const char *logEnvironVariable) noexcept;

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
      channel->LogMessage(LOC.file_name(), LOC.line() - 1, LOC.column() - 2, fmt::format(__VA_ARGS__));           \
    }                                                                                                             \
  }

#define DBGLOG(channel, ...)                                                                                      \
  if (auto channel = logging::GetLogChannel(Channel::channel); channel) {                                         \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, ::fmt::format(__VA_ARGS__));  \
  }
#else
#define DLOG(...)
#define DBGLOG(channel, ...)                                                                                      \
  if (auto channel = logging::GetLogChannel(Channel::channel); channel) {                                         \
    std::source_location srcLoc = std::source_location::current();                                                \
    channel->LogMessage(srcLoc.file_name(), srcLoc.line() - 1, srcLoc.column() - 2, ::fmt::format(__VA_ARGS__));  \
  }
#define CDLOG(...)
#endif

} // namespace mdb::logging

using PEArg = mdb::logging::ProfileEventArg;

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

template <> struct formatter<mdb::Offset> : public Default<mdb::Offset>
{
  template <typename FormatContext>
  constexpr auto
  format(const mdb::Offset &offset, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "0x{:x}", offset.value());
  }
};

} // namespace fmt