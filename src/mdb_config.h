#pragma once
#include <optional>
#include <span>
#include <string_view>

// system namespace - anything and everything that involves the configuration of mdb
namespace sys {

enum class WaitSystem
{
  UseAwaiterThread,
  UseSignalHandler,
};

struct DwarfParseConfiguration
{
  bool eager_lnp_parse;
};

class DebuggerConfiguration
{

  WaitSystem wait_system;
  std::optional<int> worker_thread_pool_size;
  DwarfParseConfiguration dwarf_parsing;

public:
  friend std::optional<DebuggerConfiguration> parse_cli(int argc, const char **argv) noexcept;
  static constexpr auto
  Default() noexcept
  {
    auto res = DebuggerConfiguration{};
    res.wait_system = WaitSystem::UseAwaiterThread;
    res.worker_thread_pool_size = std::nullopt;
    res.dwarf_parsing.eager_lnp_parse = false;
    return res;
  }

  WaitSystem waitsystem() const noexcept;
  int thread_pool_size() const noexcept;
  DwarfParseConfiguration dwarf_config() const noexcept;
};

std::optional<DebuggerConfiguration> parse_cli(int argc, const char **argv) noexcept;

}; // namespace sys