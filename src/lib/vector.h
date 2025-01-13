/** LICENSE TEMPLATE */
#pragma once
#include "lib/arena_allocator.h"
#include "utils/util.h"
#include <cstddef>
#include <cstdint>
#include <memory_resource>

namespace alloc {
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
  void Push(T&& t) noexcept {}
};

template <typename T>
class Array {
  T* mPtr;
  u64 mSize;
public:
  Array(T* finalizedBuffer, u64 size) : mPtr(finalizedBuffer), mSize(size) {}

  auto begin() noexcept {
    return mPtr;
  }

  auto end() noexcept {
    return mPtr + mSize;
  }
};

/** CollectionBuilder takes an arena allocator that can allocate new pages consecutively to previous ones - this makes
* this allocator great to use with this "collection builder" which is sort of meant to be as a temporary std::vector that "finalizes" an array.
* and because our AA can re-alloc it's internal buffer contigously, the CollectionBuilder can keep push-backing, re-alloc, push back, re alloc,
* without having to copy over it's old elements. */
template<typename T>
class CollectionBuilder {
  alloc::ArenaAllocator* mAllocator;
  T* mPtr;
  u32 mCurrentSize;
  u32 mCurrentCapacity;
public:
  explicit CollectionBuilder(alloc::ArenaAllocator* alloc) noexcept : mAllocator(alloc) {
  }

  template <typename ...Args>
  T& Emplace(Args&&... args) {
    if(mCurrentSize == mCurrentCapacity) {
      mAllocator->allocate()
    }
  }
};

} // namespace mdb