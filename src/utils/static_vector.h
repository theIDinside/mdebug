#pragma once
#include "../common.h"
#include <cmath>
#include <sys/mman.h>

namespace utils {

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