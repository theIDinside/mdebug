#pragma once
#include "macros.h"
#include <cstdint>
#include <memory>
#include <span>

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

namespace utils {

/**
 * Byte container to be used instead of std::vector. Notice that, there's no actual "mutation" methods on this
 * type. It simply hands out it's pointer, and then requests of the user to inform it of how much has been
 * written there. That's all.
 */
class ByteBuffer
{
public:
  NO_COPY(ByteBuffer)
private:
  u8 *buffer;
  u32 value_size;
  u32 capacity;

public:
  constexpr ByteBuffer(std::uint8_t *buffer, u32 cap) noexcept;

  constexpr ~ByteBuffer() noexcept
  {
    if (buffer) {
      delete[] buffer;
    }
  }

  u32 size() const noexcept;
  void set_size(u32 size) noexcept;
  void wrote_bytes(u32 bytes) noexcept;
  u8 *next() noexcept;
  std::span<u8> span() const noexcept;
  static ByteBuffer::OwnPtr create(u64 size) noexcept;
};
} // namespace utils