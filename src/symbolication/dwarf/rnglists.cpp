#include "rnglists.h"
#include "symbolication/dwarf/reader_funcs.h"
#include "symbolication/dwarf_binary_reader.h"
#include <symbolication/dwarf/die.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
namespace sym::dw {

/*static*/ ResolvedRangeListOffset
ResolvedRangeListOffset::make(sym::dw::UnitData &cu, u64 unresolved_offset) noexcept
{
  return ResolvedRangeListOffset{cu.rng_list_base() + unresolved_offset};
}

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
  ptr = decode_uleb128(ptr, out.start);
  return decode_uleb128(ptr, out.end);
}

RangeListHeader
read_header(ElfSection *rnglists, u64 offset)
{
  auto ptr = rnglists->GetPointer(offset);
  RangeListHeader header{};
  header.sec_offset = ptr - rnglists->GetPointer(0);
  ptr = read_initial_length(ptr, header.init_len, header.init_len_len);
  ptr = read_version(ptr, header.version);
  ptr = read_address_size(ptr, header.addr_size);
  ptr = read_segment_selector_size(ptr, header.segment_selector_size);
  ptr = read_offset_entry_count(ptr, header.offset_entry_count);
  return header;
}

std::vector<AddressRange>
read_boundaries(sym::dw::UnitData &cu, ResolvedRangeListOffset resolved) noexcept
{
  std::vector<AddressRange> result{};
  const auto elf = cu.GetObjectFile()->GetElf();
  auto ptr = elf->debug_rnglists->GetPointer(resolved.offset);
  RangeListEntry entry{};
  AddrPtr base = nullptr;
  ptr = read_entry_type(ptr, entry);
  const auto read_address = [&]() {
    u64 addr = *(u64 *)ptr;
    ptr += 8;
    return addr;
  };
  while (entry != RangeListEntry::DW_RLE_end_of_list) {
    switch (entry) {
    case RangeListEntry::DW_RLE_base_addressx: {
      u64 addr_index = 0;
      ptr = decode_uleb128(ptr, addr_index);
      const auto addr_ptr = elf->debug_addr->GetPointer(cu.addr_base() + addr_index * 8);
      u64 start_addr = 0;
      std::memcpy(&start_addr, addr_ptr, 8);
      base = start_addr;
      break;
    }
    case RangeListEntry::DW_RLE_startx_endx:
    case RangeListEntry::DW_RLE_startx_length: {
      u64 addr_index = 0;
      ptr = decode_uleb128(ptr, addr_index);
      u64 range_length = 0;
      ptr = decode_uleb128(ptr, range_length);
      const auto addr_ptr = elf->debug_addr->GetPointer(cu.addr_base() + (addr_index * 8));
      u64 start_addr = 0;
      std::memcpy(&start_addr, addr_ptr, 8);
      result.push_back({start_addr, start_addr + range_length});
      break;
    }
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = read_offset_pair(ptr, pair);
      result.push_back({base + pair.start, base + pair.end});
      break;
    }
    case RangeListEntry::DW_RLE_base_address: {
      base = read_address();
    } break;
    case RangeListEntry::DW_RLE_start_length: {
      AddrPtr start = read_address();
      u64 len;
      ptr = decode_uleb128(ptr, len);
      result.push_back({start, start + len});
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
    ptr = read_entry_type(ptr, entry);
  }
  return result;
}

AddressRange
read_boundaries(const ElfSection *rnglists, const u64 offset) noexcept
{
  BoundaryBuilder builder{};
  AddrPtr base = nullptr;
  auto ptr = rnglists->GetPointer(offset);
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
    case RangeListEntry::DW_RLE_startx_length: {
      u64 addr_index = 0;
      ptr = decode_uleb128(ptr, addr_index);
      u64 range_length = 0;
      ptr = decode_uleb128(ptr, range_length);
      break;
    }
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = read_offset_pair(ptr, pair);
      builder.CompareSwapHigh(base + pair.end);
      break;
    }
    case RangeListEntry::DW_RLE_base_address: {
      base = read_address();
      builder.CompareSwapLow(base);
    } break;
    case RangeListEntry::DW_RLE_start_length: {
      AddrPtr start = read_address();
      u64 len;
      ptr = decode_uleb128(ptr, len);
      builder.CompareBoundary(start, start + len);
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
    ptr = read_entry_type(ptr, entry);
  }
  return builder.Build();
}

AddressRange
read_boundaries(const ElfSection *rnglists, const RangeListHeader &header) noexcept
{
  BoundaryBuilder builder{};
  AddrPtr base = nullptr;
  auto ptr = rnglists->GetPointer(header.first_entry_offset());
  auto end = rnglists->GetPointer(header.next_header_offset());
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
      builder.CompareSwapHigh(base + pair.end);
      break;
    }
    case RangeListEntry::DW_RLE_base_address: {
      base = read_address();
      builder.CompareSwapLow(base);
    } break;
    case RangeListEntry::DW_RLE_start_length: {
      AddrPtr start = read_address();
      u64 len;
      ptr = decode_uleb128(ptr, len);
      builder.CompareBoundary(start, start + len);
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
  }
  return builder.Build();
}
} // namespace sym::dw