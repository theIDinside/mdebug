#pragma once
#include "../common.h"
#include "dwarf_defs.h"

class Elf;

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
    return *(T *)head;
  }

  template <InitLengthRead InitReadAction>
  u64
  read_initial_length() noexcept
  {
    u32 peeked = peek_value<u32>();
    if (peeked != 0xff'ff'ff'ff) {
      if constexpr (InitReadAction == UpdateBufferSize)
        set_wrapped_buffer_size(peeked + 4);
      offset_size = 4;
      return read_value<u32>();
    } else {
      head += 4;
      const auto sz = read_value<u64>();
      if constexpr (InitReadAction == UpdateBufferSize)
        set_wrapped_buffer_size(sz + 12);
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
