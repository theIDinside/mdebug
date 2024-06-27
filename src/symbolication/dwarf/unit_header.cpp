#include "unit_header.h"
#include "common.h"
#include <symbolication/elf.h>

namespace sym::dw {
// Partial/Compile Unit-header constructor
UnitHeader::UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data,
                       u64 abbrev_offset, u8 addr_size, u8 format, DwarfVersion version,
                       DwarfUnitType unit_type) noexcept
    : sec_offset(sec_offset), unit_size(unit_size), die_data(die_data), abbreviation_sec_offset(abbrev_offset),
      address_size(addr_size), dwarf_format(format), dw_version(version), unit_type(unit_type), id(id)
{
}

// Type Unit-Header constructor
UnitHeader::UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data,
                       u64 abbrev_offset, u8 addr_size, u8 format, u64 type_signature, u64 type_offset) noexcept
    : sec_offset(sec_offset), unit_size(unit_size), die_data(die_data), abbreviation_sec_offset(abbrev_offset),
      address_size(addr_size), dwarf_format(format), dw_version(DwarfVersion::D5),
      unit_type(DwarfUnitType::DW_UT_type), id(id), type_sig(type_signature), type_offset(type_offset)
{
}

u8
UnitHeader::offset_size() const noexcept
{
  return dwarf_format;
}

u8
UnitHeader::addr_size() const noexcept
{
  return address_size;
}

const u8 *
UnitHeader::abbreviation_data(const ElfSection *abbrev_sec) const noexcept
{
  ASSERT(abbrev_sec->get_name() == ".debug_abbrev",
         "Wrong ELF section was used, expected .debug_abbrev but received {}", abbrev_sec->get_name());
  return abbrev_sec->offset(abbreviation_sec_offset);
}

const u8 *
UnitHeader::data() const noexcept
{
  return die_data.data();
}

const u8 *
UnitHeader::end_excl() const noexcept
{
  return die_data.data() + die_data.size();
}

u64
UnitHeader::debug_info_offset() const noexcept
{
  return sec_offset;
}

u8
UnitHeader::format() const noexcept
{
  return dwarf_format;
}

u8
UnitHeader::header_len() const noexcept
{
  const auto fmt = format();
  ASSERT(fmt == 4 || fmt == 8, "Unknown format");
  switch (unit_type) {
  case DwarfUnitType::DW_UT_type:
    return fmt == 4 ? (4 * 6) : (4 * 10);
  case DwarfUnitType::DW_UT_compile:
    [[fallthrough]];
  case DwarfUnitType::DW_UT_partial: {
    return 4 * (3 * (fmt / 4)) - (dw_version == DwarfVersion::D4 ? 1 : 0);
  }
  default:
    ASSERT(false, "UNIT TYPE {} not yet implemented support for unit at 0x{:x}", to_str(unit_type), sec_offset);
    break;
  }
}

std::span<const u8>
UnitHeader::get_die_data() const noexcept
{
  return die_data;
}

bool
UnitHeader::spans_across(u64 offset) const noexcept
{
  return offset >= sec_offset && offset <= (sec_offset + unit_size);
}

SymbolInfoId
UnitHeader::unit_id() const noexcept
{
  return id;
}

DwarfVersion
UnitHeader::version() const noexcept
{
  return dw_version;
}

DwarfUnitType
UnitHeader::get_unit_type() const noexcept
{
  return unit_type;
}

u64
UnitHeader::cu_size() const noexcept
{
  return unit_size;
}

u64
UnitHeader::type_signature() const noexcept
{
  return type_sig;
}

u64
UnitHeader::get_type_offset() const noexcept
{
  return type_offset;
}
} // namespace sym::dw