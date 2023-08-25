#pragma once
#include "../common.h"
#include <cmath>
#include <sys/mman.h>

namespace utils {

// Not a complete interface yet - building only the currently needed parts as we go along.
template <typename T, size_t Size> class StackVector
{
public:
  StackVector() noexcept : m_size(0) {}

  constexpr auto
  front() const noexcept
  {
    ASSERT(m_size > 0, "No elements in StackVector");
    return reference(0);
  }

  constexpr auto
  back() const noexcept
  {
    return reference(m_size - 1);
  }

  template <typename... Args>
  constexpr void
  push_back(Args &&...args) noexcept
  {
    ASSERT(m_size < capacity(), "StackVector reached max capacity.");
    new (m_storage) T{std::forward<Args...>(args...)};
    m_size++;
  }

  constexpr void
  push_back(const T &t) noexcept
  {
    ASSERT(m_size < capacity(), "StackVector reached max capacity.");
    new (m_storage) T{t};
    m_size++;
  }

  constexpr void
  push_back(T &&t) noexcept
  {
    ASSERT(m_size < capacity(), "StackVector reached max capacity.");
    new (m_storage) T{std::move(t)};
    m_size++;
  }

  constexpr T &
  pop_back() noexcept
  {
    const auto last = m_size - 1;
    --m_size;
    return reference(last);
  }

  constexpr auto
  capacity() const noexcept
  {
    return Size;
  }

  constexpr auto
  size() const noexcept
  {
    return m_size;
  }

  constexpr T *
  begin() noexcept
  {
    if (m_size == 0)
      return nullptr;
    return &reference(0);
  }

  constexpr T *
  end() noexcept
  {
    if (m_size == 0)
      return nullptr;
    return (&reference(m_size - 1)) + 1;
  }

  constexpr std::span<T>
  span() const noexcept
  {
    return std::span<T>{&reference(0), m_size};
  }

private:
  constexpr T &
  reference(u64 index) const noexcept
  {
    ASSERT(index < m_size, "Index outside range of contained elements");
    return *(T *)m_storage;
  }

  std::byte m_storage[sizeof(T) * Size];
  size_t m_size;
};

// Minimum allocation of MDB_PAGE_SIZE
// Meant to hold "trivial" types.
template <typename T> class StaticVector
{
public:
  using OwnPtr = std::unique_ptr<StaticVector<T>>;
  StaticVector(u64 capacity) noexcept : size(0), cap(capacity), cap_bytes(capacity * sizeof(T))
  {
    const auto bytes_required = sizeof(T) * capacity;
    if (bytes_required < MDB_PAGE_SIZE) {
      data = mmap_buffer<T>(MDB_PAGE_SIZE);
      cap_bytes = MDB_PAGE_SIZE;
    } else {
      const auto pages_required =
          std::ceil(static_cast<double>(bytes_required) / static_cast<double>(MDB_PAGE_SIZE));
      cap_bytes = MDB_PAGE_SIZE * static_cast<u64>(pages_required);
      data = mmap_buffer<T>(cap_bytes);
    }
  }

  ~StaticVector() noexcept { munmap(data, cap_bytes); }

  void
  set_size(u64 size) noexcept
  {
    this->size = size;
  }

  void
  push(T &&t) noexcept
  {
    *(data + size) = t;
  }

  template <typename U = T>
  U *
  data_ptr() noexcept
  {
    return (U *)data;
  }

  std::span<T>
  span() noexcept
  {
    return std::span<T>{data, size};
  }

private:
  T *data;
  u64 size;
  u64 cap;
  u64 cap_bytes;
};
} // namespace utils