#include "mdb_config.h"
#include "fmt/core.h"
#include "utils/logger.h"
#include <charconv>
#include <getopt.h>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <variant>

namespace sys {
static constexpr auto OptArgRequired = 1;
static constexpr auto OptNoArgument = 0;

std::optional<int>
parse_int(std::string_view str)
{
  int result{};
  auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);

  if (ec == std::errc())
    return result;
  else
    return std::nullopt;
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

std::optional<DebuggerConfiguration>
parse_cli(int argc, const char **argv) noexcept
{
  auto init = DebuggerConfiguration::Default();
  int option_index = 0;
  int opt;
  option long_opts[]{// flags
                     {"rr", OptNoArgument, 0, 'r'},
                     {"eager-lnp-parse", OptNoArgument, 0, 'e'},
                     // parameters
                     {"thread-pool-size", OptArgRequired, 0, 't'}};

  // Using getopt to parse command line options
  while ((opt = getopt_long(argc, const_cast<char *const *>(argv), "ret:", long_opts, &option_index)) != -1) {
    switch (opt) {
    case 0:
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
      DLOG("mdb", "Usage: mdb [-r]");
      exit(-1);
      return std::nullopt;
      break;
    default:
      continue;
    }
  }
  return init;
}
} // namespace sys