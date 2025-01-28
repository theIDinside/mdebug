/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "dwarf_defs.h"
#include <type_traits>
#include <typedefs.h>
namespace mdb {
class Elf;

static constexpr u8 LEB128_MASK = 0b0111'1111;

const u8 *
decode_uleb128(const u8 *data, IsBitsType auto &value) noexcept
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
decode_leb128(const u8 *data, IsBitsType auto &value) noexcept
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
      : buffer(bc.begin()), head(bc.begin()), end(bc.end()), size(bc.size()), bookmarks(), elf(elf)
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC *bc)
      : buffer(bc->begin()), head(bc->begin()), end(bc->end()), size(bc->size()), bookmarks(), elf(elf)
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC &bc, u64 offset)
      : buffer(bc.offset(offset)), head(bc.offset(offset)), end(bc.end()), size(bc.size() - offset), bookmarks(),
        elf(elf)
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const Elf *elf, const BC *bc, u64 offset)
      : buffer(bc->offset(offset)), head(bc->offset(offset)), end(bc->end()), size(bc->size() - offset),
        bookmarks(), elf(elf)
  {
  }

  explicit DwarfBinaryReader(std::span<const u8> data) noexcept;

  template <typename T>
    requires(!std::is_pointer_v<T>)
  constexpr T
  read_value() noexcept
  {
    ASSERT(remaining_size() >= sizeof(T),
           "Buffer has not enough data left to read value of size {} (bytes left={})", sizeof(T),
           remaining_size());
    using Type = typename std::remove_cv_t<T>;
    constexpr auto sz = sizeof(Type);
    Type value = *(Type *)head;
    head += sz;
    return value;
  }

  template <typename T>
    requires(!std::is_pointer_v<T>)
  constexpr void
  skip_value() noexcept
  {
    ASSERT(remaining_size() >= sizeof(T),
           "Buffer has not enough data left to read value of size {} (bytes left={})", sizeof(T),
           remaining_size());
    using Type = typename std::remove_cv_t<T>;
    constexpr auto sz = sizeof(Type);
    head += sz;
  }

  template <ByteCode T>
  constexpr T
  read_byte() noexcept
  {
    const auto res = head;
    ++head;
    return (T)*res;
  }

  template <typename T, size_t N>
  constexpr void
  read_into_array(std::array<T, N> &out)
  {
    for (auto &elem : out) {
      elem = read_value<T>();
    }
  }

  template <typename T>
  T
  peek_value() noexcept
  {
    static_assert(!std::is_reference<T>::value, "reference types not allowed");
    // Previous version did *(T*)head - which technically works on Linux, but it is U.B. in C++ actually :(
    alignas(T) T result;
    std::memcpy(&result, head, sizeof(T));
    return result;
  }

  template <InitLengthRead InitReadAction>
  u64
  read_initial_length() noexcept
  {
    u32 peeked = peek_value<u32>();
    if (peeked != 0xff'ff'ff'ff) {
      if constexpr (InitReadAction == UpdateBufferSize) {
        set_wrapped_buffer_size(peeked + 4);
      }
      offset_size = 4;
      return read_value<u32>();
    } else {
      head += 4;
      const auto sz = read_value<u64>();
      if constexpr (InitReadAction == UpdateBufferSize) {
        set_wrapped_buffer_size(sz + 12);
      }
      offset_size = 8;
      return sz;
    }
  }

  /** Reads value from buffer according to dwarf spec, which can determine size of addresess, offsets etc. We
   * always make the results u64, but DWARF might represent the data as 32-bit values etc.*/
  u64 dwarf_spec_read_value() noexcept;
  template <IsBitsType T>
  constexpr auto
  read_uleb128() noexcept
  {
    T value;
    head = decode_uleb128(head, value);
    return value;
  }

  template <IsBitsType T>
  T
  read_leb128() noexcept
  {
    T value;
    head = decode_leb128(head, value);
    return value;
  }

  std::span<const u8> get_span(u64 size) noexcept;
  std::string_view read_string() noexcept;
  void skip_string() noexcept;
  DataBlock read_block(u64 size) noexcept;

  /**
   * @brief Reads an 'offset value' from the binary data stream. The offset size is determined when reading the
   * initial length (unit length) of a unit header in one of the many DWARF sections.
   *
   * @return u64 - the offset value found at the current position in the data stream.
   */
  u64 read_offset() noexcept;
  const u8 *current_ptr() const noexcept;
  bool has_more() noexcept;
  u64 remaining_size() const noexcept;
  u64 bytes_read() const noexcept;
  void skip(i64 bytes) noexcept;

  // sets a mark at the "currently read to bytes", to be able to compare at some time later how many bytes have
  // been read since that mark, by popping that mark and comparing
  void bookmark() noexcept;

  // pops the latest bookmark and subtracts current head position - that position, which calculates how many bytes
  // has been read since then
  u64 pop_bookmark() noexcept;

  friend DwarfBinaryReader sub_reader(const DwarfBinaryReader &reader) noexcept;

  u64 read_content_index(AttributeForm form) noexcept;
  std::string_view read_content_str(AttributeForm form) noexcept;
  DataBlock read_content_datablock(AttributeForm form) noexcept;
  std::variant<std::string_view, u64, DataBlock> read_content(AttributeForm form) noexcept;

private:
  void set_wrapped_buffer_size(u64 size) noexcept;
  const u8 *buffer;
  const u8 *head;
  const u8 *end;
  u64 size;
  u8 offset_size = 4;
  std::vector<u64> bookmarks;
  const Elf *elf;
};

} // namespace mdb