#include "mdb_config.h"
#include "fmt/core.h"
#include "fmt/ranges.h"
#include "log.h"
#include "utils/logger.h"
#include "utils/util.h"
#include "utils/worker_task.h"
#include <charconv>
#include <filesystem>
#include <getopt.h>
#include <string_view>
#include <sys/user.h>
#include <thread>
#include <unistd.h>

namespace sys {
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

void
LogConfig::configure_logging(bool taskgroup_log) noexcept
{
  mdb::log::Config::SetLogTaskGroup(taskgroup_log);
}

WaitSystem
DebuggerConfiguration::waitsystem() const noexcept
{
  return wait_system;
}

int
DebuggerConfiguration::thread_pool_size() const noexcept
{
  constexpr auto get_default = []() {
    const auto cpus = std::thread::hardware_concurrency();
    return cpus > 4 ? cpus / 2 : cpus;
  };
  return worker_thread_pool_size.value_or(get_default());
}

LogConfig
DebuggerConfiguration::log_config() const noexcept
{
  return log;
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

static constexpr auto LongOptions = std::to_array<option>({{"rr", OptNoArgument, 0, 'r'},
                                                           // parameters
                                                           {"thread-pool-size", OptArgRequired, 0, 't'},
                                                           {"log", OptArgRequired, 0, 'l'},
                                                           {"perf", OptNoArgument, 0, 'p'},
                                                           {"log-directory", OptArgRequired, 0, 'd'}});

static constexpr auto USAGE_STR =
  "Usage: mdb <communication path> [-r|-t <thread pool size>|-l <eh,dwarf,mdb,dap,awaiter>]\n"
  "\n"
  "-d <directory>\n"
  "\t The directory where log files should be saved.";
utils::Expected<DebuggerConfiguration, CLIError>
parse_cli(int argc, const char **argv) noexcept
{
  auto init = DebuggerConfiguration::Default();
  int option_index = 0;
  int opt; // NOLINT

  // Using getopt to parse command line options
  while ((opt = getopt_long(argc, const_cast<char *const *>(argv), "rt:l:d:p", LongOptions.data(), // NOLINT
                            &option_index)) != -1) {
    switch (opt) {
    case 0:
      break;
    case 'd': {
      if (optarg) {
        std::string_view args{optarg};
        Path pathArg = Path{args}.lexically_normal();
        if (pathArg.is_relative()) {
          init.mLogDirectory = (std::filesystem::current_path() / pathArg).lexically_normal();
        } else {
          init.mLogDirectory = std::move(pathArg);
        }
      } else {
        return utils::unexpected(CLIError{.info = CLIErrorInfo::BadArgValue, .msg = USAGE_STR});
      }
    } break;
    case 'l':
      if (optarg) {
        std::string_view args{optarg};
        auto input_logs = utils::split_string(args, ",");
        if (const auto res = LogConfig::verify_ok(input_logs); !res.is_expected()) {
          return utils::unexpected(CLIError{.info = CLIErrorInfo::BadArgValue,
                                            .msg = fmt::format("Unknown log value: {}\nSupported: ", res.error(),
                                                               fmt::join(LogConfig::LOGS, ","))});
        }
        for (auto i : input_logs) {
          init.log.set(i);
        }
      } else {
        return utils::unexpected(CLIError{.info = CLIErrorInfo::BadArgValue, .msg = USAGE_STR});
      }
      break;
    case 'p':
      init.log.time_log = true;
      break;
    case 'r':
      // If '-r' is found, set the flag
      init.wait_system = WaitSystem::UseSignalHandler;
      break;
    case 't':
      if (optarg) {
        init.worker_thread_pool_size = parse_int(std::string_view{optarg});
      }
      break;
    case '?': {
      DBGLOG(core, "Usage: mdb [-r|-e|-t <thread pool size>|-l <eh,dwarf,mdb,dap,awaiter>]");
      auto cliErrorMessage = fmt::format("Unknown argument: {}\n\n{}", argv[optind], USAGE_STR);
      return utils::unexpected(
        CLIError{.info = CLIErrorInfo::UnknownArgs, .msg = std::move(cliErrorMessage)}); // NOLINT
    }
    default:
      continue;
    }
  }
  return init;
}
} // namespace sys