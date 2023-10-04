#pragma once
#include <mutex>
#include <shared_mutex>

template <typename T, typename Mutex = std::shared_mutex> class Synchronized
{
public:
  explicit Synchronized(T t) noexcept : t(t), mutex() {}
  explicit Synchronized(T &&t) noexcept : t(std::move(t)), mutex() {}
  Synchronized(const Synchronized &copy);

  // Convenience member function
  // Think of "cbegin" or "cend"; when we have a non-const object, but we want to treat it as a const,
  // because for all intents and purposes (at that point in time) we are not going to mutate it.
  const Synchronized &
  as_const() const
  {
    return *this;
  }

  // The writer lock
  class WriterLockPtr
  {
  public:
    using WLock = WriterLockPtr;

    WriterLockPtr() = delete;
    explicit WriterLockPtr(Synchronized *sync_object) noexcept : sync_obj(sync_object)
    {
      if (sync_object)
        sync_object->mutex.lock();
    }

    WriterLockPtr(const WLock &rhs) : sync_obj(rhs.sync_obj)
    {
      if (sync_obj)
        sync_obj->mutex.lock();
    }

    WriterLockPtr(WLock &&rhs) : sync_obj(rhs.sync_obj) { rhs.sync_obj = nullptr; }

    WriterLockPtr &
    operator=(WLock &&rhs) noexcept
    {
      if (this != &rhs) {
        if (sync_obj)
          sync_obj->mutex.unlock();
        sync_obj = rhs.sync_obj;
        rhs.sync_obj = nullptr;
      }
      return *this;
    }

    WriterLockPtr &
    operator=(const WLock &rhs) noexcept
    {
      if (this != &rhs) {
        // We're changing a sync object to give up a critical section that it is holding already, to hold a new CS,
        // thus we must first make sure to unlock our critical section
        if (sync_obj)
          sync_obj->mutex.unlock();
        sync_obj = rhs.sync_obj;
        if (sync_obj)
          sync_obj->mutex.lock();
      }
      return *this;
    }

    ~WriterLockPtr() noexcept
    {
      if (sync_obj)
        sync_obj->mutex.unlock();
    }

    T *
    operator->() noexcept
    {
      return sync_obj ? &sync_obj->t : nullptr;
    }

  private:
    Synchronized *sync_obj;
  };

  WriterLockPtr
  writer_lock()
  {
    return WriterLockPtr(this);
  }

  WriterLockPtr
  operator->()
  {
    return WriterLockPtr(this);
  }

  // The reader lock
  class ReaderLockPtr
  {
  public:
    ReaderLockPtr() = delete;
    explicit ReaderLockPtr(const Synchronized *sync_object) noexcept : sync_obj(sync_object)
    {
      ASSERT(sync_obj != nullptr, "Sync object was null");
      sync_obj->mutex.lock_shared();
    }

    const T *
    operator->() noexcept
    {
      return nullptr;
    }

  private:
    Synchronized *sync_obj;
  };

  ReaderLockPtr
  operator->() const
  {
    return ReaderLockPtr(this);
  }

  ReaderLockPtr
  reader_lock() const
  {
    return ReaderLockPtr(this);
  }

  ReaderLockPtr
  reader_lock()
  {
    return ReaderLockPtr(&this->as_const());
  }

private:
  T t;
  // Needs to be mutable, since we mutate it in const-methods
  mutable Mutex mutex;
};