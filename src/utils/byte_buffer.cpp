/** LICENSE TEMPLATE */
#include "byte_buffer.h"
#include <common.h>
#include <cstring>

namespace mdb {
constexpr ByteBuffer::ByteBuffer(std::pmr::memory_resource *allocator, u32 cap) noexcept
    : mCapacity(cap), mAllocator(allocator)
{
  mBuffer = (u8 *)mAllocator->allocate(cap, 32);
  mSize = 0;
}

constexpr ByteBuffer::ByteBuffer(std::uint8_t *buffer, u32 cap) noexcept
    : mBuffer(buffer), mSize(0), mCapacity(cap), mAllocator(nullptr)
{
}

u32
ByteBuffer::Write(std::span<const u8> data) noexcept
{
  const auto dataSize = data.size_bytes();
  MDB_ASSERT(mSize + dataSize <= mCapacity, "Not enough space in buffer.");
  std::memcpy(Next(), data.data(), dataSize);
  WroteBytes(dataSize);
  return dataSize;
}

u32
ByteBuffer::Size() const noexcept
{
  return mSize;
}

void
ByteBuffer::SetSize(u32 new_size) noexcept
{
  MDB_ASSERT(new_size <= mCapacity, "Setting size beyond capacity is illogical");
  mSize = new_size;
}

void
ByteBuffer::WroteBytes(u32 bytes) noexcept
{
  mSize += bytes;
  MDB_ASSERT(mSize <= mCapacity, "Recorded size exceeded capacity");
}

std::span<u8>
ByteBuffer::Span() const noexcept
{
  return std::span{ mBuffer, mSize };
}

u8 *
ByteBuffer::Next() noexcept
{
  return mBuffer + mSize;
}

/*static*/
std::unique_ptr<ByteBuffer>
ByteBuffer::Create(u64 size) noexcept
{
  auto *ptr = new u8[size];
  return std::make_unique<ByteBuffer>(ptr, size);
}

/*static*/
std::unique_ptr<ByteBuffer>
ByteBuffer::create(std::pmr::memory_resource *allocator, u64 size) noexcept
{
  return std::make_unique<ByteBuffer>(allocator, size);
}

} // namespace mdb