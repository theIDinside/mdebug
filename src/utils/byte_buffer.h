/** LICENSE TEMPLATE */
#pragma once
#include <common/macros.h>
#include <common/typedefs.h>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <span>

namespace mdb {
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
  u8 *mBuffer;
  u32 mSize;
  u32 mCapacity;
  std::pmr::memory_resource *mAllocator;

public:
  constexpr ByteBuffer(std::pmr::memory_resource *allocator, u32 cap) noexcept;
  constexpr ByteBuffer(std::uint8_t *buffer, u32 cap) noexcept;

  constexpr ~ByteBuffer() noexcept
  {
    if (mBuffer && !mAllocator) {
      delete[] mBuffer;
    } else {
      mAllocator->deallocate(mBuffer, mCapacity);
    }
  }

  u32 Write(std::span<const u8> data) noexcept;
  [[nodiscard]] u32 Size() const noexcept;
  void SetSize(u32 size) noexcept;
  void WroteBytes(u32 bytes) noexcept;
  u8 *Next() noexcept;
  [[nodiscard]] std::span<u8> Span() const noexcept;
  static ByteBuffer::OwnPtr Create(u64 size) noexcept;
  static ByteBuffer::OwnPtr create(std::pmr::memory_resource *allocator, u64 size) noexcept;
};
} // namespace mdb