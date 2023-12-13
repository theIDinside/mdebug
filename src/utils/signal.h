#pragma once
#include "../common.h"
#include <array>
#include <csignal>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <vector>

namespace utils {
class ScopedBlockedSignals
{
  sigset_t restore_to;
  sigset_t newly_set;

public:
  template <size_t N>
  ScopedBlockedSignals(std::array<int, N> signals_to_block) noexcept : restore_to(), newly_set()
  {
    sigemptyset(&newly_set);
    for (const auto sig : signals_to_block) {
      if (-1 == sigaddset(&newly_set, sig)) {
        PANIC(fmt::format("Adding signal {} to set failed", sig));
      }
    }
    if (-1 == pthread_sigmask(SIG_BLOCK, &newly_set, &restore_to)) {
      PANIC("Failed to block signals.");
    }
  }

  ~ScopedBlockedSignals() noexcept
  {
    if (-1 == pthread_sigmask(SIG_SETMASK, &restore_to, nullptr)) {
      PANIC("Failed to restore signals.");
    }
  }
};
}; // namespace utils