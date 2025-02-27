/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include <cstring>
#include <memory>
#include <memory_resource>
#include <type_traits>

namespace mdb {

template <typename T, typename El>
concept RemovePolicy = requires(El *e, std::uint32_t index, std::uint32_t size) { T::PostRemove(e, index, size); };

class DynShiftRemovePolicy
{
public:
  template <typename T>
  constexpr static void
  PostRemove(T *data, std::uint32_t index, std::uint32_t size) noexcept
  {
    for (auto i = index; i < size - 1;) {
      data[i++] = std::move(data + i);
    }
  }
};

class SwapBackRemovePolicy
{
public:
  template <typename T>
  constexpr static void
  PostRemove(T *data, std::uint32_t index, std::uint32_t size) noexcept
  {
    data[index] = std::move(data[size - 1]);
  }
};

template <typename T, RemovePolicy<T> RemovingPolicy> class DynArray
{
  std::pmr::memory_resource *mAllocatorResource;
  T *mData;
  std::uint32_t mSize;
  std::uint32_t mCapacity;

  static consteval auto
  Alignment() noexcept -> uint32_t
  {
    constexpr auto width = std::bit_width(sizeof(T));
    // If N is already a power of two, return N
    if ((1U << (width - 1)) == sizeof(T)) {
      return sizeof(T);
    }

    // Otherwise, return the next power of two
    return 1U << width;
  }

  constexpr void
  ExtendAllocation() noexcept
  {
    ExtendAllocationBy(mCapacity * 1.5);
  }

  constexpr void
  ExtendAllocationBy(std::uint32_t newCapacity) noexcept
  {
    auto tmp = mData;
    const auto oldCapacity = mCapacity;
    mCapacity = newCapacity;
    mData = static_cast<T *>(mAllocatorResource->allocate(mCapacity * sizeof(T), Alignment()));
    // If the new allocation couldn't be mapped in right behind the current one, we need to copy elements.
    if (mData != tmp && tmp != nullptr) {
      std::move(tmp, tmp + mSize, mData);
      mAllocatorResource->deallocate(tmp, oldCapacity, sizeof(T));
    }
  }

public:
  constexpr DynArray(std::pmr::memory_resource *alloc = std::pmr::new_delete_resource()) noexcept
      : mAllocatorResource(alloc), mData(nullptr), mSize(0), mCapacity(0)
  {
  }

  constexpr DynArray(std::uint32_t capacity,
                     std::pmr::memory_resource *alloc = std::pmr::new_delete_resource()) noexcept
      : mAllocatorResource(alloc), mSize(0), mCapacity(capacity)
  {
    mData = static_cast<T *>(mAllocatorResource->allocate(mCapacity * sizeof(T), Alignment()));
  }

  constexpr ~DynArray() noexcept
    requires(std::is_trivially_destructible_v<T>)
  {
    mAllocatorResource->deallocate(mData, mCapacity * sizeof(T), sizeof(T));
  }

  constexpr void
  Reserve(std::uint32_t capacity) noexcept
  {
    if (capacity <= mCapacity) {
      return;
    }
    ExtendAllocationBy(capacity);
  }

  constexpr ~DynArray() noexcept
    requires(!std::is_trivially_destructible_v<T>)
  {
    std::destroy(mData, mData + mSize);
    mAllocatorResource->deallocate(mData, mCapacity * sizeof(T), sizeof(T));
  }

  constexpr T *
  Get(std::uint32_t index) noexcept
  {
    if (index >= mSize) {
      return nullptr;
    }
    return mData[index];
  }

  constexpr T *
  AddUninit() noexcept
  {
    if (mSize == mCapacity) {
      ExtendAllocation();
    }
    ASSERT(mSize != mCapacity, "Allocation was not extended.");
    const auto i = mSize++;
    return mData + i;
  }

  template <typename... Args>
  constexpr void
  Add(Args &&...args) noexcept
  {
    std::construct_at(mData[mSize++], std::forward<Args>(args)...);
  }

  template <typename... Args>
  constexpr T *
  Push(Args &&...args) noexcept
  {
    return std::construct_at(mData[mSize++], std::forward<Args>(args)...);
  }

  constexpr bool
  RemoveAt(std::uint32_t index) noexcept
  {
    if (index < mSize) {
      std::destroy_at(mData[index]);
      RemovingPolicy::PostRemove(mData, index, mSize);
      --mSize;
      return true;
    }
    return false;
  }

  constexpr std::span<T>
  Span() noexcept
  {
    return std::span{mData, mSize};
  }

  constexpr std::span<const T>
  Span() const noexcept
  {
    return std::span{mData, mSize};
  }

  constexpr bool
  IsEmpty() const noexcept
  {
    return mSize == 0;
  }
};

} // namespace mdb