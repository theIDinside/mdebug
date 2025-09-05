/** LICENSE TEMPLATE */
#include "config.h"

// mdb
#include <configuration/command_line.h>
#include <utility>
#include <utils/logger.h>
#include <utils/util.h>

// std
#include <cctype>
#include <filesystem>
#include <thread>
// system

namespace mdb::cfg {

InitializationConfiguration *
InitializationConfiguration::ConfigureWithParser(CommandLineRegistry &parser) noexcept
{
  auto *config = new InitializationConfiguration{};
  // When recorded using rr, hardware concurrency actually reports 1 ! which -2 would give us 4.5 billion threads.
  // No wonder mdb blows up under rr record.
  const auto minimumThreadPoolSize =
    std::thread::hardware_concurrency() > 4 ? (std::thread::hardware_concurrency() - 2) : 2;

  parser.AddOption<ArgIterator &>("-t",
    "--threads",
    "Configure the worker thread pool size. Defaults to amount of threads on system minus specific debugger "
    "threads.",
    config->mThreadPoolSize,
    &FromTraits<size_t>::From,
    minimumThreadPoolSize);

  parser.AddOption<ArgIterator &>(
    "-l",
    "--log",
    "The directory where log files should be saved. If that directory doesn't exist, it will not be created for "
    "you, and mdb will terminate.",
    config->mLogDirectory,
    [](ArgIterator &it) noexcept -> ParseResult<fs::path> {
      auto arg = TryExpected(it);
      if (fs::exists(arg)) {
        return fs::path{ arg };
      }
      return it.Error(ParseErrorType::DirectoryDoesNotExist);
    },
    fs::current_path());

  parser.AddOption<ArgIterator &>(
    "-i",
    "--interface",
    "Parameter that configures how to communicate with MDB. The default value for this is standard IO (the "
    "process' stdout/stdin). If a path-like string is given, MDB will attempt to open a UNIX domain socket "
    "there and subsequently, the debug adapter client will communicate over this socket using the debug adapter "
    "protocol. JSON config path: communication.interface.type: 'stdio' | ('/tmp/sock' | 'unix:/tmp/sock').",
    config->mDebugAdapterInterface,
    [](ArgIterator &it) -> ParseResult<DebugAdapterInterface> {
      auto arg = TryExpected(it);
      std::string lowered;
      lowered.reserve(arg.size());
      for (const auto c : arg) {
        lowered.push_back(std::tolower(c));
      }

      if (lowered == "stdio") {
        return UseStdio{};
      }

      auto kind = arg.find_first_of(':');

      Transport defaultTransport = Transport::UnixSocket;

      if (kind != arg.npos) {
        auto transport = arg.substr(0, kind);
        arg.remove_prefix(kind + 1);
        // MAYBE TODO: Future may support tcp:, ... etc
        if (transport != "unix") {
          return it.Error(ParseErrorType::InvalidFormat);
        }
      }

      const auto checkIsInTmp = [](const fs::path &subDirOftmp) noexcept {
        // /tmp is return by this fn.
        fs::path AllowedRoot = fs::temp_directory_path();
        // for each in (a, b) in zipped: (break condition: a or b hit its .end())
        for (const auto &[root, branch] : std::views::zip(AllowedRoot, subDirOftmp)) {
          if (root != branch) {
            return false;
          }
        }
        return true;
      };

      switch (defaultTransport) {
      case Transport::UnixSocket: {
        const auto suppliedPath = fs::weakly_canonical(arg);
        if (!checkIsInTmp(suppliedPath)) {
          return it.Error(ParseErrorType::SocketPathNotAllowed);
        }
        if (fs::exists(arg)) {
          return it.Error(ParseErrorType::DebugAdapterSocketPathAlreadyTaken);
        }
        return UnixSocket{ arg };
      } break;
      }
      std::unreachable();
    },
    UseStdio{});

  parser.AddOption<ArgIterator &>("-w",
    "--timeout",
    "Sets the amount of time MDB will wait for an incoming connection to communicate using DAP on a specified "
    "socket. If no socket path has been provided, this value will be ignored, as the default configuration is to "
    "use stdio.",
    config->mWaitForConnectionTimeout,
    FromTraits<int>::From,
    5000);

#define LOG_HELP(channel, name, help) "\n - " #channel ": " help

  parser.AddEnvironmentVariable<std::vector<Channel>>("LOG",
    "Configure what logging channels should be opened\n" FOR_EACH_LOG(LOG_HELP),
    config->mLogChannels,
    [](auto stringView) -> ParseResult<std::vector<Channel>> {
      std::vector<Channel> result{};
      auto splits = SplitString(stringView, ',');
      if (std::ranges::any_of(splits, [](std::string_view cfg) { return cfg == "all"; })) {
        auto channels = Enum<Channel>::Variants();
        CopyTo(channels, result);
        return result;
      }

      result.reserve(splits.size());
      for (const auto &el : splits) {
        if (const auto chan = Enum<Channel>::FromString(el); chan) {
          result.push_back(*chan);
        }
      }
      return result;
    });

  return config;
}
} // namespace mdb::cfg