/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "utils/logger.h"
#include <array>
#include <csignal>
#include <cstring>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

namespace mdb {
class ScopedBlockedSignals
{
  sigset_t mRestoreTo;
  sigset_t mNewlySet;

public:
  template <size_t N> ScopedBlockedSignals(std::array<int, N> signalsToBlock) noexcept : mRestoreTo(), mNewlySet()
  {
    sigemptyset(&mNewlySet);
    std::string signalNames;
    for (int signal : signalsToBlock) {
      fmt::format_to(std::back_inserter(signalNames), "{}", strsignal(signal));
      if (signal != signalsToBlock.back()) {
        signalNames.push_back(',');
      }
    }
    DBGLOG(core, "{} Configuring to block signals: {}", gettid(), signalNames);
    for (const auto sig : signalsToBlock) {
      if (-1 == sigaddset(&mNewlySet, sig)) {
        PANIC(fmt::format("Adding signal {} to set failed", sig));
      }
    }
    if (-1 == pthread_sigmask(SIG_BLOCK, &mNewlySet, &mRestoreTo)) {
      PANIC("Failed to block signals.");
    }
  }

  ~ScopedBlockedSignals() noexcept
  {
    if (-1 == pthread_sigmask(SIG_SETMASK, &mRestoreTo, nullptr)) {
      PANIC("Failed to restore signals.");
    }
  }
};
}; // namespace mdb