/** LICENSE TEMPLATE */
#pragma once
#include <typedefs.h>

// TODO(simon): Re-name & refactor this to mean "section offset"?
struct Offset
{
  u64 i;
  constexpr operator u64() const noexcept { return i; }
  constexpr u64
  value() const noexcept
  {
    return i;
  }

  friend i64
  operator-(const Offset &a, const Offset &b) noexcept
  {
    return static_cast<i64>(a.i) - static_cast<i64>(b.i);
  }

  friend i64
  operator+(const Offset &a, const Offset &b) noexcept
  {
    return static_cast<i64>(a.i) + static_cast<i64>(b.i);
  }
};

struct Index
{
  constexpr operator u32() const noexcept { return i; }
  constexpr u32
  value() const noexcept
  {
    return i;
  }

  friend i64
  operator-(const Index &a, const Index &b) noexcept
  {
    return static_cast<i64>(a.i) - static_cast<i64>(b.i);
  }

  friend i64
  operator+(const Index &a, const Index &b) noexcept
  {
    return static_cast<i64>(a.i) + static_cast<i64>(b.i);
  }

  Index
  operator++(int) noexcept
  {
    const auto tmp = *this;
    this->i++;
    return tmp;
  }

  Index &
  operator++() noexcept
  {
    this->i++;
    return *this;
  }

  u32 i;
};