#include "mdb_config.h"
#include "fmt/core.h"
#include "utils/logger.h"
#include "utils/util.h"
#include <charconv>
#include <getopt.h>
#include <string_view>
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
  SetTaskGroupLog(taskgroup_log);
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

DwarfParseConfiguration
DebuggerConfiguration::dwarf_config() const noexcept
{
  return dwarf_parsing;
}

LogConfig
DebuggerConfiguration::log_config() const noexcept
{
  return log;
}

static constexpr auto LongOptions = std::to_array<option>({{"rr", OptNoArgument, 0, 'r'},
                                                           {"eager-lnp-parse", OptNoArgument, 0, 'e'},
                                                           // parameters
                                                           {"thread-pool-size", OptArgRequired, 0, 't'},
                                                           {"log", OptArgRequired, 0, 'l'},
                                                           {"perf", OptNoArgument, 0, 'p'}});

static constexpr auto USAGE_STR =
  "Usage: mdb <communication path> [-r|-e|-t <thread pool size>|-l <eh,dwarf,mdb,dap,awaiter>]";
utils::Expected<DebuggerConfiguration, CLIError>
parse_cli(int argc, const char **argv) noexcept
{
  auto init = DebuggerConfiguration::Default();
  int option_index = 0;
  int opt;

  // Using getopt to parse command line options
  while ((opt = getopt_long(argc, const_cast<char *const *>(argv), "ret:l:p", LongOptions.data(),
                            &option_index)) != -1) {
    switch (opt) {
    case 0:
      break;
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
    case 'e':
      init.dwarf_parsing.eager_lnp_parse = true;
      break;
    case '?':
      DBGLOG(core, "Usage: mdb [-r|-e|-t <thread pool size>|-l <eh,dwarf,mdb,dap,awaiter>]");
      return utils::unexpected(
        CLIError{.info = CLIErrorInfo::UnknownArgs,
                 .msg = fmt::format("{}\n\nUnknown argument: {}", USAGE_STR, argv[optind])});
      break;
    default:
      continue;
    }
  }
  return init;
}
} // namespace sys