/** LICENSE TEMPLATE */
#pragma once
#include "symbolication/dwarf_defs.h"
#include <common.h>

namespace mdb::sym::dw {

constexpr const u8 *
ReadInitialLength(const u8 *ptr, u64 &out, u8 &init_len_len) noexcept
{
  u32 peeked = *(u32 *)(ptr);
  if (peeked != 0xff'ff'ff'ff) {
    ptr += 4;
    init_len_len = 4;
    out = peeked;
    return ptr;
  } else {
    ptr += 4;
    out = *(u64 *)ptr;
    ptr += 8;
    init_len_len = 12;
    return ptr;
  }
}

constexpr const u8 *
ReadVersion(const u8 *ptr, DwarfVersion &version) noexcept
{
  u16 value = *(u16 *)ptr;
  ptr += 2;
  MDB_ASSERT(value == 4 || value == 5, "Only DWARF 4 or 5 is supported");
  if (value == 4) {
    version = DwarfVersion::D4;
  } else {
    version = DwarfVersion::D5;
  }
  return ptr;
}

constexpr const u8 *
ReadAddrSize(const u8 *ptr, u8 &addrSize) noexcept
{
  addrSize = *ptr;
  ++ptr;
  return ptr;
}
constexpr const u8 *
ReadSegmentSelectorSize(const u8 *ptr, u8 &segmentSelectorSize) noexcept
{
  segmentSelectorSize = *ptr;
  ++ptr;
  return ptr;
}

constexpr const u8 *
ReadOffsetEntryCount(const u8 *ptr, u32 &offsetEntryCount) noexcept
{
  offsetEntryCount = *(u32 *)ptr;
  ptr += 4;
  return ptr;
}
} // namespace mdb::sym::dw