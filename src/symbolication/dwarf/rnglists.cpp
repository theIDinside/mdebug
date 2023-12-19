#include "rnglists.h"
#include "common.h"
#include "symbolication/dwarf/reader_funcs.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_defs.h"
#include <symbolication/block.h>
#include <symbolication/elf.h>
namespace sym::dw {

u32
RangeListHeader::first_entry_offset() const noexcept
{
  return sec_offset + StaticHeaderSize + init_len_len;
}

u32
RangeListHeader::next_header_offset() const noexcept
{
  return sec_offset + StaticHeaderSize + init_len_len + init_len;
}

static const u8 *
read_entry_type(const u8 *ptr, RangeListEntry &entry) noexcept
{
  entry = *(RangeListEntry *)ptr;
  ++ptr;
  return ptr;
}

struct OffsetPair
{
  u64 start, end;
};

static const u8 *
read_offset_pair(const u8 *ptr, OffsetPair &out) noexcept
{
  u64 *cast = (u64 *)ptr;
  out.start = *cast;
  ++cast;
  out.end = *cast;
  ++cast;
  return (const u8 *)cast;
}

RangeListHeader
read_header(ElfSection *rnglists, u64 offset)
{
  auto ptr = rnglists->offset(offset);
  RangeListHeader header{};
  header.sec_offset = ptr - rnglists->offset(0);
  ptr = read_initial_length(ptr, header.init_len, header.init_len_len);
  ptr = read_version(ptr, header.version);
  ptr = read_address_size(ptr, header.addr_size);
  ptr = read_segment_selector_size(ptr, header.segment_selector_size);
  ptr = read_offset_entry_count(ptr, header.offset_entry_count);
  return header;
}

AddressRange
read_boundaries(const ElfSection *rnglists, const u64 offset) noexcept
{
  BoundaryBuilder builder{};
  AddrPtr base = nullptr;
  auto ptr = rnglists->offset(offset);
  const auto read_address = [&]() {
    u64 addr = *(u64 *)ptr;
    ptr += 8;
    return addr;
  };

  RangeListEntry entry{};
  ptr = read_entry_type(ptr, entry);
  while (entry != RangeListEntry::DW_RLE_end_of_list) {
    switch (entry) {
    case RangeListEntry::DW_RLE_base_addressx:
    case RangeListEntry::DW_RLE_startx_endx:
    case RangeListEntry::DW_RLE_startx_length:
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = read_offset_pair(ptr, pair);
      builder.compare_swap_high(base + pair.end);
      break;
    }
    case RangeListEntry::DW_RLE_base_address: {
      base = read_address();
      builder.compare_swap_low(base);
    } break;
    case RangeListEntry::DW_RLE_start_length: {
      AddrPtr start = read_address();
      u64 len;
      ptr = decode_uleb128(ptr, len);
      builder.compare_boundary(start, start + len);
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
    ptr = read_entry_type(ptr, entry);
  }
  return builder.build();
}

AddressRange
read_boundaries(const ElfSection *rnglists, const RangeListHeader &header) noexcept
{
  BoundaryBuilder builder{};
  AddrPtr base = nullptr;
  auto ptr = rnglists->offset(header.first_entry_offset());
  auto end = rnglists->offset(header.next_header_offset());
  const auto read_address = [&]() {
    u64 addr = *(u64 *)ptr;
    ptr += 8;
    return addr;
  };
  while (ptr < end) {
    RangeListEntry entry{};
    ptr = read_entry_type(ptr, entry);
    switch (entry) {
    case RangeListEntry::DW_RLE_base_addressx:
    case RangeListEntry::DW_RLE_startx_endx:
    case RangeListEntry::DW_RLE_startx_length:
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = read_offset_pair(ptr, pair);
      builder.compare_swap_high(base + pair.end);
      break;
    }
    case RangeListEntry::DW_RLE_base_address: {
      base = read_address();
      builder.compare_swap_low(base);
    } break;
    case RangeListEntry::DW_RLE_start_length: {
      AddrPtr start = read_address();
      u64 len;
      ptr = decode_uleb128(ptr, len);
      builder.compare_boundary(start, start + len);
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
  }
  return builder.build();
}
} // namespace sym::dw