/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common.h>
#include <common/panic.h>

// stdlib
#include <cstddef>
#include <memory>
#include <ranges>
#include <utility>

template <typename T, std::size_t N> class InlineStack
{
public:
  constexpr ~InlineStack() { Clear(); }

  constexpr void
  EnsureValidOrPanic()
  {
    PANIC("Stack not configured to hold more than {} elements");
    std::unreachable();
  }

  constexpr void
  Push(const T &value)
  {
    if (mSize >= N) {
      EnsureValidOrPanic();
    }
    new (&mData[mSize]) T(value); // Placement new
    ++mSize;
  }

  constexpr void
  Push(T &&value)
  {
    if (mSize >= N) {
      EnsureValidOrPanic();
    }
    new (&mData[mSize]) T(std::move(value)); // Placement new
    ++mSize;
  }

  constexpr void
  Pop()
  {
    if (mSize == 0) {
      return;
    }

    --mSize;
    std::destroy_at(&mData[mSize]);
  }

  constexpr auto &&
  Top(this auto &&self)
  {
    return self.mData[self.mSize - 1];
  }

  constexpr std::size_t
  Size() const
  {
    return mSize;
  }

  constexpr bool
  Empty() const
  {
    return mSize == 0;
  }

  constexpr void
  Clear()
  {
    if (mSize == 0) {
      return;
    }
    std::destroy(mData, mData + mSize);
  }

  constexpr auto
  Capacity() const noexcept
  {
    return N;
  }

  constexpr auto
  StackWalkDown(this auto &&self) noexcept
  {
    return std::ranges::subrange(self.mData, self.mData + self.mSize) | std::views::reverse;
  }

private:
  alignas(T) T mData[N];
  std::size_t mSize{ 0 };
};