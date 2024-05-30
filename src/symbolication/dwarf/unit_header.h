#pragma once
#include <cstdint>
#include <span>
#include <symbolication/dwarf/common.h>
#include <symbolication/dwarf_defs.h>
#include <typedefs.h>

struct ElfSection;

namespace sym::dw {

class UnitHeader
{
public:
  UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data, u64 abbrev_offset,
             u8 addr_size, u8 format, DwarfVersion version, DwarfUnitType unit_type) noexcept;
  u8 offset_size() const noexcept;
  u8 addr_size() const noexcept;
  const u8 *abbreviation_data(const ElfSection *abbrev_sec) const noexcept;
  const u8 *data() const noexcept;
  const u8 *end_excl() const noexcept;
  u64 debug_info_offset() const noexcept;
  u8 format() const noexcept;
  u8 header_len() const noexcept;
  std::span<const u8> get_die_data() const noexcept;
  bool spans_across(u64 sec_offset) const noexcept;
  SymbolInfoId unit_id() const noexcept;
  DwarfVersion version() const noexcept;
  DwarfUnitType get_unit_type() const noexcept;
  u64 cu_size() const noexcept;

private:
  u64 sec_offset;
  u64 unit_size;
  std::span<const u8> die_data;
  u64 abbreviation_sec_offset;
  u8 address_size;
  u8 dwarf_format;
  DwarfVersion dw_version;
  DwarfUnitType unit_type;
  SymbolInfoId id;
};
} // namespace sym::dw