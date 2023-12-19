#pragma once
#include <cstdint>
#include <symbolication/dwarf_defs.h>

struct ElfSection;
struct AddressRange;
using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

namespace sym::dw {
struct RangeListHeader
{
  static constexpr auto StaticHeaderSize = 10;
  u32 sec_offset;
  u64 init_len;
  u8 init_len_len;
  DwarfVersion version;
  u8 addr_size;
  u8 segment_selector_size;
  u32 offset_entry_count;
  u32 first_entry_offset() const noexcept;
  u32 next_header_offset() const noexcept;
};

AddressRange read_boundaries(const ElfSection *rnglists, const RangeListHeader &header) noexcept;
AddressRange read_boundaries(const ElfSection *rnglists, const u64 offset) noexcept;
} // namespace sym::dw