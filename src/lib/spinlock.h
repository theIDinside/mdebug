/** LICENSE TEMPLATE */
#pragma once
#include <atomic>

class SpinLock
{
public:
  SpinLock();
  void lock() noexcept;
  void unlock() noexcept;

private:
  std::atomic<unsigned int> m_flag;
};