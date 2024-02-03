#pragma once
#include <array>
#include <cstdint>
#include <cstring>

using u8 = std::uint64_t;
using u64 = std::uint64_t;
// Primitive Optional. An optional that holds primitives and holds an exclusive discriminator value of 0. So 0 can
// not be represented by the values held

template <typename T> class DOptional
{
  T value;

public:
  static_assert(sizeof(T) <= sizeof(u64), "Max allowed size for this type is currently 8 bytes");

  constexpr NonZeroOptional(T t) noexcept : value(t)
  {
    static_assert(static_cast<u64>(t) != 0, "Engaging a NonZeroOptional with a 0 values is not allowed. "
                                            "Use NoneZeroOptional::None to represent no value.");
  }

  constexpr bool
  has_value() const noexcept
  {
    u64 bytes = 0;
    std::memcpy(bytes, &value, sizeof(bytes));
    return bytes != 0;
  }
};