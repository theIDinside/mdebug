/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common.h>
#include <common/typedefs.h>
#include <symbolication/dwarf_defs.h>

// system
#include <cstring>
#include <type_traits>
namespace mdb {
class Elf;

static constexpr u8 LEB128_MASK = 0b0111'1111;

const u8 *
DecodeUleb128(const u8 *data, IsBitsType auto &value) noexcept
{
  u64 res = 0;
  u64 shift = 0;
  u8 index = 0;
  for (;;) {
    u8 byte = data[index];
    res |= ((byte & LEB128_MASK) << shift);
    ASSERT(!(shift == 63 && byte != 0x0 && byte != 0x1), "Decoding of ULEB128 failed at index {}", index);
    ++index;
    if ((byte & ~LEB128_MASK) == 0) {
      // We don't want C++ to set a "good" enum value
      // if `value` is of type enum. We literally want a bit blast here (and we rely on that being the case)
      std::memcpy(&value, &res, sizeof(decltype(value)));
      return data + index;
    }
    shift += 7;
  }
}

const u8 *
DecodeLeb128(const u8 *data, IsBitsType auto &value) noexcept
{
  i64 res = 0;
  u64 shift = 0;
  u8 index = 0;
  u64 size = 64;
  u8 byte;
  for (;;) {
    byte = data[index];
    ASSERT(!(shift == 63 && byte != 0x0 && byte != 0x7f), "Decoding of LEB128 failed at index {}", index);
    res |= ((byte & LEB128_MASK) << shift);
    shift += 7;
    ++index;
    if ((byte & ~LEB128_MASK) == 0) {
      break;
    }
  }
  if (shift < size && (byte & 0x40)) {
    res |= ((-1) << shift);
  }
  // We don't want C++ to set a "good" enum value
  // if `value` is of type enum. We literally want a bit blast here (and we rely on that being the case)
  std::memcpy(&value, &res, sizeof(decltype(value)));
  return data + index;
}

// clang-format off
template <typename BufferType>
concept ByteContainer = requires(BufferType t) {
  { t.size() } -> std::convertible_to<u64>;
  { t.begin() } -> std::convertible_to<const u8 *>;
  { t.end() } -> std::convertible_to<const u8 *>;
  { t.offset(10) } -> std::convertible_to<const u8 *>;
};

template <typename ByteType>
concept ByteCode = requires(ByteType bt) {
  { std::to_underlying(bt) } -> std::convertible_to<u8>;
} && std::is_enum<ByteType>::value;
// clang-format on

class DwarfBinaryReader
{
public:
  enum class InitLengthRead
  {
    UpdateBufferSize,
    Ignore
  };

  using enum InitLengthRead;

  DwarfBinaryReader(const Elf *elf, const u8 *buffer, u64 size) noexcept;
  DwarfBinaryReader(const Elf *elf, std::span<const u8> buffer) noexcept;
  DwarfBinaryReader(const DwarfBinaryReader &reader) noexcept;

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC &bc)
      : mBuffer(bc.begin()), mHead(bc.begin()), mEnd(bc.end()), mSize(bc.size()), mBookmarks(), mElf(elf)
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC *bc)
      : mBuffer(bc->begin()), mHead(bc->begin()), mEnd(bc->end()), mSize(bc->size()), mBookmarks(), mElf(elf)
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC &bc, u64 offset)
      : mBuffer(bc.offset(offset)), mHead(bc.offset(offset)), mEnd(bc.end()), mSize(bc.size() - offset),
        mBookmarks(), mElf(elf)
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC *bc, u64 offset)
      : mBuffer(bc->offset(offset)), mHead(bc->offset(offset)), mEnd(bc->end()), mSize(bc->size() - offset),
        mBookmarks(), mElf(elf)
  {
  }

  explicit DwarfBinaryReader(std::span<const u8> data) noexcept;

  template <typename T>
    requires(!std::is_pointer_v<T>)
  constexpr T
  ReadValue() noexcept
  {
    ASSERT(RemainingSize() >= sizeof(T),
      "Buffer has not enough data left to read value of size {} (bytes left={})",
      sizeof(T),
      RemainingSize());
    using Type = typename std::remove_cv_t<T>;
    constexpr auto sz = sizeof(Type);
    Type value = *(Type *)mHead;
    mHead += sz;
    return value;
  }

  template <typename T>
    requires(!std::is_pointer_v<T>)
  constexpr void
  SkipValue() noexcept
  {
    ASSERT(RemainingSize() >= sizeof(T),
      "Buffer has not enough data left to read value of size {} (bytes left={})",
      sizeof(T),
      RemainingSize());
    using Type = typename std::remove_cv_t<T>;
    constexpr auto sz = sizeof(Type);
    mHead += sz;
  }

  template <ByteCode T>
  constexpr T
  ReadByte() noexcept
  {
    const auto res = mHead;
    ++mHead;
    return (T)*res;
  }

  template <typename T, size_t N>
  constexpr void
  ReadIntoArray(std::array<T, N> &out)
  {
    for (auto &elem : out) {
      elem = ReadValue<T>();
    }
  }

  template <typename T>
  T
  PeekValue() noexcept
  {
    static_assert(!std::is_reference<T>::value, "reference types not allowed");
    // Previous version did *(T*)head - which technically works on Linux, but it is U.B. in C++ actually :(
    alignas(T) T result;
    std::memcpy(&result, mHead, sizeof(T));
    return result;
  }

  template <InitLengthRead InitReadAction>
  u64
  ReadInitialLength() noexcept
  {
    u32 peeked = PeekValue<u32>();
    if (peeked != 0xff'ff'ff'ff) {
      if constexpr (InitReadAction == UpdateBufferSize) {
        SetWrappedBufferSize(peeked + 4);
      }
      mOffsetSize = 4;
      return ReadValue<u32>();
    } else {
      mHead += 4;
      const auto sz = ReadValue<u64>();
      if constexpr (InitReadAction == UpdateBufferSize) {
        SetWrappedBufferSize(sz + 12);
      }
      mOffsetSize = 8;
      return sz;
    }
  }

  /** Reads value from buffer according to dwarf spec, which can determine size of addresess, offsets etc. We
   * always make the results u64, but DWARF might represent the data as 32-bit values etc.*/
  u64 DwarfSpecReadValue() noexcept;
  template <IsBitsType T>
  constexpr auto
  ReadUleb128() noexcept
  {
    T value;
    mHead = DecodeUleb128(mHead, value);
    return value;
  }

  template <IsBitsType T>
  T
  ReadLeb128() noexcept
  {
    T value;
    mHead = DecodeLeb128(mHead, value);
    return value;
  }

  std::span<const u8> GetSpan(u64 size) noexcept;
  std::string_view ReadString() noexcept;
  void SkipString() noexcept;
  DataBlock ReadBlock(u64 size) noexcept;

  /**
   * @brief Reads an 'offset value' from the binary data stream. The offset size is determined when reading the
   * initial length (unit length) of a unit header in one of the many DWARF sections.
   *
   * @return u64 - the offset value found at the current position in the data stream.
   */
  u64 ReadOffset() noexcept;
  const u8 *CurrentPtr() const noexcept;
  bool HasMore() noexcept;
  u64 RemainingSize() const noexcept;
  u64 BytesRead() const noexcept;
  void Skip(i64 bytes) noexcept;

  // sets a mark at the "currently read to bytes", to be able to compare at some time later how many bytes have
  // been read since that mark, by popping that mark and comparing
  void Bookmark() noexcept;

  // pops the latest bookmark and subtracts current head position - that position, which calculates how many bytes
  // has been read since then
  u64 PopBookmark() noexcept;

  friend DwarfBinaryReader SubReader(const DwarfBinaryReader &reader) noexcept;

  u64 ReadContentIndex(AttributeForm form) noexcept;
  std::string_view ReadContentStr(AttributeForm form) noexcept;
  DataBlock ReadContentDatablock(AttributeForm form) noexcept;
  std::variant<std::string_view, u64, DataBlock> ReadContent(AttributeForm form) noexcept;

private:
  void SetWrappedBufferSize(u64 size) noexcept;
  const u8 *mBuffer;
  const u8 *mHead;
  const u8 *mEnd;
  u64 mSize;
  u8 mOffsetSize = 4;
  std::vector<u64> mBookmarks;
  const Elf *mElf;
};

} // namespace mdb