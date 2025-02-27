/** LICENSE TEMPLATE */
#pragma once
#include "lib/arena_allocator.h"
#include "utils/util.h"
#include <cstddef>
#include <cstdint>
#include <memory_resource>

namespace mdb::alloc {
class ArenaAllocator;
}

namespace mdb {

using u32 = std::uint32_t;
using u64 = std::uint64_t;

template <typename T, std::size_t InlineSize> class SBOVector
{
  T mInlined[InlineSize];

public:
  explicit SBOVector() noexcept;
};

// A "normal" std::vector-like vector. Only it uses allocators,
// and comes with a better (in my opinion) interface. Because we choose u32/u32 as size and cap, instead of u64, we
// maintain the same size as std::vector, but with better allocator customization
template <typename T> class Vector
{
  T *mPtr;
  u32 mSize{0};
  u32 mCapacity;
  std::pmr::memory_resource *mAllocator;

public:
  Vector(u32 capacity) noexcept : mPtr(mAllocator->allocate(sizeof(T) * capacity, 64)), mCapacity(capacity) {}
  void
  Push(T &&t) noexcept
  {
  }
};
} // namespace mdb