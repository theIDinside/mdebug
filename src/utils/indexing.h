#pragma once
#include <cstdint>

using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u16 = std::uint16_t;
using u8 = std::uint8_t;

using i64 = std::int64_t;
using i32 = std::int32_t;
using i16 = std::int16_t;
using i8 = std::int8_t;

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