/** LICENSE TEMPLATE */
#pragma once
#include <symbolication/dwarf_defs.h>
#include <typedefs.h>
#include <vector>

namespace sym::dw {
class UnitData;
}

class Elf;
struct ElfSection;
struct AddressRange;

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

struct ResolvedRangeListOffset
{
  u64 offset;
  static ResolvedRangeListOffset make(sym::dw::UnitData &cu, u64 unresolved_offset) noexcept;
};

AddressRange read_boundaries(const ElfSection *rnglists, const RangeListHeader &header) noexcept;
AddressRange read_boundaries(const ElfSection *rnglists, const u64 offset) noexcept;
std::vector<AddressRange> read_boundaries(sym::dw::UnitData &cu, ResolvedRangeListOffset offset) noexcept;
} // namespace sym::dw