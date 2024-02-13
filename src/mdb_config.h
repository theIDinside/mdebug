#pragma once
#include "awaiter.h"
#include "utils/expected.h"
#include "utils/worker_task.h"
#include <optional>
#include <span>
#include <string_view>
#include <unordered_set>

// system namespace - anything and everything that involves the configuration of mdb
namespace sys {

enum class CLIErrorInfo
{
  UnknownArgs,
  BadArgValue
};

struct CLIError
{
  CLIErrorInfo info;
  std::string msg;
};

// Awaiter thread should be used in most circumstances; but this system won't function under RR (yet).
// So if MDB is to be recorded by RR, the signal handler system should be used instead.
enum class WaitSystem
{
  UseAwaiterThread,
  UseSignalHandler,
};

struct DwarfParseConfiguration
{
  bool eager_lnp_parse;
};

template <typename ConfigType> struct Setting
{
  std::string_view setting;
  ConfigType boolean;
};

using namespace std::string_view_literals;
struct LogConfig
{
  static constexpr auto LOGS = std::to_array({"eh"sv, "dwarf"sv, "mdb"sv, "dap"sv, "awaiter"sv});
  union
  {
    struct
    {
      bool eh = false;
      bool dwarf = false;
      bool mdb = false;
      bool dap = false;
      bool awaiter = false;
    };
    bool arr[5];
  };
  bool time_log = false;

  static utils::Expected<bool, std::string_view>
  verify_ok(const std::span<std::string_view> &parsed) noexcept
  {
    std::unordered_set<std::string_view> logs{LogConfig::LOGS.begin(), LogConfig::LOGS.end()};
    for (const auto i : parsed) {
      if (!logs.contains(i))
        return utils::unexpected(i);
    }
    return true;
  }

  constexpr void
  set(std::string_view log) noexcept
  {
    auto it = std::ranges::find(std::cbegin(LOGS), std::cend(LOGS), log);
    if (it != std::end(LOGS)) {
      auto idx = std::distance(LOGS.begin(), it);
      arr[idx] = true;
    }
  }

  void configure_logging(bool taskgroup_log) noexcept;
};

class DebuggerConfiguration
{

  WaitSystem wait_system{WaitSystem::UseAwaiterThread};
  std::optional<int> worker_thread_pool_size{std::nullopt};
  DwarfParseConfiguration dwarf_parsing{false};
  LogConfig log{};

public:
  friend utils::Expected<DebuggerConfiguration, CLIError> parse_cli(int argc, const char **argv) noexcept;
  static constexpr auto
  Default() noexcept
  {
    auto res = DebuggerConfiguration{};
    return res;
  }

  WaitSystem waitsystem() const noexcept;
  int thread_pool_size() const noexcept;
  DwarfParseConfiguration dwarf_config() const noexcept;
  LogConfig log_config() const noexcept;
};

utils::Expected<DebuggerConfiguration, CLIError> parse_cli(int argc, const char **argv) noexcept;

}; // namespace sys