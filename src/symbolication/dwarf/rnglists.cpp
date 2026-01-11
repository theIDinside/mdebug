/** LICENSE TEMPLATE */
#include "rnglists.h"
#include "symbolication/dwarf/reader_funcs.h"
#include "symbolication/dwarf_binary_reader.h"
#include <symbolication/dwarf/die.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/todo.h>
namespace mdb::sym::dw {

/*static*/ ResolvedRangeListOffset
ResolvedRangeListOffset::Make(sym::dw::UnitData &compUnit, u64 unresolvedOffset) noexcept
{
  return ResolvedRangeListOffset{compUnit.RangeListBase() + unresolvedOffset};
}

u32
RangeListHeader::FirstEntryOffset() const noexcept
{
  return mSectionOffset + StaticHeaderSize + mInitLengthLength;
}

u32
RangeListHeader::NextHeaderOffset() const noexcept
{
  return mSectionOffset + StaticHeaderSize + mInitLengthLength + mInitLength;
}

static const u8 *
ReadEntryType(const u8 *ptr, RangeListEntry &entry) noexcept
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
ReadOffsetPair(const u8 *ptr, OffsetPair &out) noexcept
{
  ptr = DecodeUleb128(ptr, out.start);
  return DecodeUleb128(ptr, out.end);
}

RangeListHeader
ReadHeader(ElfSection *rnglists, u64 offset)
{
  auto ptr = rnglists->GetPointer(offset);
  RangeListHeader header{};
  header.mSectionOffset = ptr - rnglists->GetPointer(0);
  ptr = ReadInitialLength(ptr, header.mInitLength, header.mInitLengthLength);
  ptr = ReadVersion(ptr, header.mVersion);
  ptr = ReadAddrSize(ptr, header.mAddrSize);
  ptr = ReadSegmentSelectorSize(ptr, header.mSegmentSelectorSize);
  ptr = ReadOffsetEntryCount(ptr, header.mOffsetEntryCount);
  return header;
}

std::vector<AddressRange>
ReadBoundaries(sym::dw::UnitData &cu, ResolvedRangeListOffset resolved) noexcept
{
  std::vector<AddressRange> result{};
  const auto elf = cu.GetObjectFile()->GetElf();
  auto ptr = elf->mDebugRnglists->GetPointer(resolved.mOffset);
  RangeListEntry entry{};
  AddrPtr base = nullptr;
  ptr = ReadEntryType(ptr, entry);
  const auto read_address = [&]() {
    u64 addr = *(u64 *)ptr;
    ptr += 8;
    return addr;
  };
  while (entry != RangeListEntry::DW_RLE_end_of_list) {
    switch (entry) {
    case RangeListEntry::DW_RLE_base_addressx: {
      u64 addrIndex = 0;
      ptr = DecodeUleb128(ptr, addrIndex);
      const auto addr_ptr = elf->mDebugAddr->GetPointer(cu.AddressBase() + addrIndex * 8);
      u64 startAddr = 0;
      std::memcpy(&startAddr, addr_ptr, 8);
      base = startAddr;
      break;
    }
    case RangeListEntry::DW_RLE_startx_endx:
    case RangeListEntry::DW_RLE_startx_length: {
      u64 addrIndex = 0;
      ptr = DecodeUleb128(ptr, addrIndex);
      u64 rangeLength = 0;
      ptr = DecodeUleb128(ptr, rangeLength);
      const auto addr_ptr = elf->mDebugAddr->GetPointer(cu.AddressBase() + (addrIndex * 8));
      u64 startAddr = 0;
      std::memcpy(&startAddr, addr_ptr, 8);
      result.push_back({startAddr, startAddr + rangeLength});
      break;
    }
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = ReadOffsetPair(ptr, pair);
      result.push_back({base + pair.start, base + pair.end});
      break;
    }
    case RangeListEntry::DW_RLE_base_address: {
      base = read_address();
    } break;
    case RangeListEntry::DW_RLE_start_length: {
      AddrPtr start = read_address();
      u64 len;
      ptr = DecodeUleb128(ptr, len);
      result.push_back({start, start + len});
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
    ptr = ReadEntryType(ptr, entry);
  }
  return result;
}

AddressRange
ReadBoundaries(const ElfSection *rnglists, const u64 offset) noexcept
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
  ptr = ReadEntryType(ptr, entry);
  while (entry != RangeListEntry::DW_RLE_end_of_list) {
    switch (entry) {
    case RangeListEntry::DW_RLE_base_addressx:
    case RangeListEntry::DW_RLE_startx_endx:
    case RangeListEntry::DW_RLE_startx_length: {
      u64 addrIndex = 0;
      ptr = DecodeUleb128(ptr, addrIndex);
      u64 rangeLength = 0;
      ptr = DecodeUleb128(ptr, rangeLength);
      break;
    }
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = ReadOffsetPair(ptr, pair);
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
      ptr = DecodeUleb128(ptr, len);
      builder.CompareBoundary(start, start + len);
      break;
    }
    case RangeListEntry::DW_RLE_end_of_list:
      base = nullptr;
      break;
    }
    ptr = ReadEntryType(ptr, entry);
  }
  return builder.Build();
}

AddressRange
ReadBoundaries(const ElfSection *rnglists, const RangeListHeader &header) noexcept
{
  BoundaryBuilder builder{};
  AddrPtr base = nullptr;
  auto ptr = rnglists->GetPointer(header.FirstEntryOffset());
  auto end = rnglists->GetPointer(header.NextHeaderOffset());
  const auto read_address = [&]() {
    u64 addr = *(u64 *)ptr;
    ptr += 8;
    return addr;
  };
  while (ptr < end) {
    RangeListEntry entry{};
    ptr = ReadEntryType(ptr, entry);
    switch (entry) {
    case RangeListEntry::DW_RLE_base_addressx:
    case RangeListEntry::DW_RLE_startx_endx:
    case RangeListEntry::DW_RLE_startx_length:
    case RangeListEntry::DW_RLE_start_end:
      TODO("RLE type not yet implemented");
      break;
    case RangeListEntry::DW_RLE_offset_pair: {
      OffsetPair pair{};
      ptr = ReadOffsetPair(ptr, pair);
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
      ptr = DecodeUleb128(ptr, len);
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
} // namespace mdb::sym::dw