/** LICENSE TEMPLATE */
#include "spinlock.h"
#include <ctime>

void
SpinLock::lock() noexcept
{
  static timespec ns = {0, 2};
  auto &ns_ = ns.tv_nsec;
  auto inc = 0;
  for (auto i = 0; m_flag.load(std::memory_order_relaxed) || m_flag.exchange(1, std::memory_order_acquire); ++i) {
    if (i == 8) {
      i = 0;
      nanosleep(&ns, nullptr);
      ++inc;
    }
    if (inc > 8) {
      ns_ += 1;
    }
  }
}

void
SpinLock::unlock() noexcept
{
  m_flag.store(0, std::memory_order_release);
}

SpinLock::SpinLock() : m_flag(0) {}
