/** LICENSE TEMPLATE */
#pragma once
#include <cmath>
#include <common/typedefs.h>
#include <cstring>
#include <immintrin.h>
#include <memory>
#include <memory_resource>
#include <span>

namespace mdb {

// For use with ArenaAllocator where we blink away the contents at the end at some time.
template <typename T> class LeakVector
{
  LeakVector(u64 capacity, std::pmr::memory_resource *resource) noexcept
      : size(0), cap(capacity), cap_bytes(capacity * sizeof(T))
  {
    const auto bytes_required = sizeof(T) * capacity;
    cap_bytes = bytes_required;
    data = static_cast<T *>(resource->allocate(cap_bytes, sizeof(T)));
  }

public:
  static std::unique_ptr<LeakVector<T>>
  Create(u64 capacity, std::pmr::memory_resource *resource)
  {
    return std::unique_ptr<LeakVector<T>>(new LeakVector<T>{capacity, resource});
  }

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
} // namespace mdb