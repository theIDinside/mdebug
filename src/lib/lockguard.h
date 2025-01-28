/** LICENSE TEMPLATE */
#pragma once
namespace mdb {
template <typename Lock>
concept Lockable = requires(Lock lock) {
  lock.lock();
  lock.unlock();
};

template <Lockable Lock> class LockGuard
{
public:
  LockGuard(Lock &lock) noexcept : m_locked(lock) { m_locked.lock(); }
  ~LockGuard() noexcept { m_locked.unlock(); }

private:
  Lock &m_locked;
};
} // namespace mdb