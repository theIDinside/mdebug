#pragma once
#include "symbolication/dwarf_defs.h"
#include <common.h>
#include <concepts>
#include <cstdint>

namespace sym::dw {

constexpr const u8 *
read_initial_length(const u8 *ptr, u64 &out, u8 &init_len_len) noexcept
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
read_version(const u8 *ptr, DwarfVersion &version) noexcept
{
  u16 value = *(u16 *)ptr;
  ptr += 2;
  ASSERT(value == 4 || value == 5, "Only DWARF 4 or 5 is supported");
  if (value == 4) {
    version = DwarfVersion::D4;
  } else {
    version = DwarfVersion::D5;
  }
  return ptr;
}

constexpr const u8 *
read_address_size(const u8 *ptr, u8 &addr_size) noexcept
{
  addr_size = *ptr;
  ++ptr;
  return ptr;
}
constexpr const u8 *
read_segment_selector_size(const u8 *ptr, u8 &segment_selector_size) noexcept
{
  segment_selector_size = *ptr;
  ++ptr;
  return ptr;
}

constexpr const u8 *
read_offset_entry_count(const u8 *ptr, u32 &offset_entry_count) noexcept
{
  offset_entry_count = *(u32 *)ptr;
  ptr += 4;
  return ptr;
}
} // namespace sym::dw