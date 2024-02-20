#include "byte_buffer.h"
#include <common.h>

namespace utils {

constexpr ByteBuffer::ByteBuffer(std::uint8_t *buffer, u32 cap) noexcept
    : buffer(buffer), value_size(0), capacity(cap)
{
}

u32
ByteBuffer::size() const noexcept
{
  return value_size;
}

void
ByteBuffer::set_size(u32 new_size) noexcept
{
  ASSERT(new_size <= capacity, "Setting size beyond capacity is illogical");
  value_size = new_size;
}

void
ByteBuffer::wrote_bytes(u32 bytes) noexcept
{
  value_size += bytes;
  ASSERT(value_size <= capacity, "Recorded size exceeded capacity");
}

std::span<u8>
ByteBuffer::span() const noexcept
{
  return std::span{buffer, value_size};
}

u8 *
ByteBuffer::next() noexcept
{
  return buffer + value_size;
}

/*static*/
std::unique_ptr<ByteBuffer>
ByteBuffer::create(u64 size) noexcept
{
  auto ptr = new u8[size];
  return std::make_unique<ByteBuffer>(ptr, size);
}
} // namespace utils