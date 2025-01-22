/** LICENSE TEMPLATE */
#pragma once
#include "macros.h"
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <span>
#include <typedefs.h>

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
  using OwnPtr = std::unique_ptr<ByteBuffer>;
private:
  u8 *buffer;
  u32 value_size;
  u32 capacity;
  std::pmr::memory_resource* mAllocator;

public:
  constexpr ByteBuffer(std::pmr::memory_resource* allocator, u32 cap) noexcept;
  constexpr ByteBuffer(std::uint8_t *buffer, u32 cap) noexcept;

  constexpr ~ByteBuffer() noexcept
  {
    if (buffer && !mAllocator) {
      delete[] buffer;
    } else {
      mAllocator->deallocate(buffer, capacity);
    }
  }

  u32 size() const noexcept;
  void set_size(u32 size) noexcept;
  void wrote_bytes(u32 bytes) noexcept;
  u8 *next() noexcept;
  std::span<u8> span() const noexcept;
  static ByteBuffer::OwnPtr create(u64 size) noexcept;
  static ByteBuffer::OwnPtr create(std::pmr::memory_resource* allocator, u64 size) noexcept;
};
} // namespace utils