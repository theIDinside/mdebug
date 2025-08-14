/** LICENSE TEMPLATE */
#include "mdb_config.h"
#include "utils/logger.h"
#include <charconv>
#include <filesystem>
#include <getopt.h>
#include <string_view>
#include <sys/user.h>
#include <thread>
#include <unistd.h>

namespace mdb::sys {
static constexpr auto OptArgRequired = 1;
static constexpr auto OptNoArgument = 0;

std::optional<int>
parse_int(std::string_view str)
{
  int result{};
  auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);

  if (ec == std::errc()) {
    return result;
  } else {
    return std::nullopt;
  }
}

WaitSystem
DebuggerConfiguration::GetWaitSystemConfig() const noexcept
{
  return mWaitSystem;
}

int
DebuggerConfiguration::ThreadPoolSize() const noexcept
{
  constexpr auto get_default = []() {
    const auto cpus = std::thread::hardware_concurrency();
    return cpus > 4 ? cpus / 2 : cpus;
  };
  return mThreadPoolSize.value_or(get_default());
}

const Path &
DebuggerConfiguration::LogDirectory() const noexcept
{
  if (mLogDirectory.empty()) {
    static Path currentDir = std::filesystem::current_path();
    return currentDir;
  }
  return mLogDirectory;
}

static constexpr auto LongOptions = std::to_array<option>({ { "rr", OptNoArgument, 0, 'r' },
  // parameters
  { "thread-pool-size", OptArgRequired, 0, 't' },
  { "log-directory", OptArgRequired, 0, 'd' } });

static constexpr auto USAGE_STR =
  "Usage: mdb <communication path> [-r|-t <thread pool size>|-l <eh,dwarf,mdb,dap,awaiter>]\n"
  "\n"
  "-d <directory>\n"
  "\t The directory where log files should be saved.";
mdb::Expected<DebuggerConfiguration, CLIError>
ParseCommandLineArguments(int argc, const char **argv) noexcept
{
  auto init = DebuggerConfiguration::Default();
  int option_index = 0;
  int opt; // NOLINT

  // Using getopt to parse command line options
  while ((opt = getopt_long(argc,
            const_cast<char *const *>(argv),
            "rt:l:d:p",
            LongOptions.data(), // NOLINT
            &option_index)) != -1) {
    switch (opt) {
    case 0:
      break;
    case 'd': {
      if (optarg) {
        std::string_view args{ optarg };
        Path pathArg = Path{ args }.lexically_normal();
        if (pathArg.is_relative()) {
          init.mLogDirectory = (std::filesystem::current_path() / pathArg).lexically_normal();
        } else {
          init.mLogDirectory = std::move(pathArg);
        }
      } else {
        return mdb::unexpected(CLIError{ .info = CLIErrorInfo::BadArgValue, .msg = USAGE_STR });
      }
    } break;
    case 'r':
      // If '-r' is found, set the flag
      init.mWaitSystem = WaitSystem::UseSignalHandler;
      break;
    case 't':
      if (optarg) {
        init.mThreadPoolSize = parse_int(std::string_view{ optarg });
      }
      break;
    case '?': {
      DBGLOG(core, "Usage: mdb [-r|-t <thread pool size>|-d <log output directory>]");
      auto cliErrorMessage = std::format("Unknown argument: {}\n\n{}", argv[optind], USAGE_STR);
      return mdb::unexpected(
        CLIError{ .info = CLIErrorInfo::UnknownArgs, .msg = std::move(cliErrorMessage) }); // NOLINT
    }
    default:
      continue;
    }
  }
  return init;
}
} // namespace mdb::sys