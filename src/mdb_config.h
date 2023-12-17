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

class DebuggerInitialization
{

  WaitSystem wait_system;
  std::optional<int> worker_thread_pool_size;

public:
  friend std::optional<DebuggerInitialization> parse_cli(int argc, const char **argv) noexcept;
  static constexpr auto
  Default() noexcept
  {
    auto res = DebuggerInitialization{};
    res.wait_system = WaitSystem::UseAwaiterThread;
    res.worker_thread_pool_size = std::nullopt;
    return res;
  }

  WaitSystem waitsystem() const noexcept;
  int thread_pool_size() const noexcept;
};

std::optional<DebuggerInitialization> parse_cli(int argc, const char **argv) noexcept;

}; // namespace sys