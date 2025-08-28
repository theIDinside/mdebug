/** LICENSE TEMPLATE */
#include "unit_header.h"
#include <symbolication/elf.h>
#include <utils/logger.h>
namespace mdb::sym::dw {
// Partial/Compile Unit-header constructor
UnitHeader::UnitHeader(SymbolInfoId id,
  u64 sec_offset,
  u64 unit_size,
  std::span<const u8> die_data,
  u64 abbrev_offset,
  u8 addr_size,
  u8 format,
  DwarfVersion version,
  DwarfUnitType unit_type) noexcept
    : mSecOffset(sec_offset), mUnitSize(unit_size), mDieData(die_data), mAbbreviationSectionOffset(abbrev_offset),
      mAddrSize(addr_size), mDwarfFormat(format), mDwarfVersion(version), mUnitType(unit_type), mId(id)
{
}

// Type Unit-Header constructor
UnitHeader::UnitHeader(SymbolInfoId id,
  u64 sec_offset,
  u64 unit_size,
  std::span<const u8> die_data,
  u64 abbrev_offset,
  u8 addr_size,
  u8 format,
  u64 type_signature,
  u64 type_offset) noexcept
    : mSecOffset(sec_offset), mUnitSize(unit_size), mDieData(die_data), mAbbreviationSectionOffset(abbrev_offset),
      mAddrSize(addr_size), mDwarfFormat(format), mDwarfVersion(DwarfVersion::D5),
      mUnitType(DwarfUnitType::DW_UT_type), mId(id), mTypeSignature(type_signature), mTypeOffset(type_offset)
{
}

u8
UnitHeader::OffsetSize() const noexcept
{
  return mDwarfFormat;
}

u8
UnitHeader::AddrSize() const noexcept
{
  return mAddrSize;
}

const u8 *
UnitHeader::AbbreviationData(const ElfSection *abbrev_sec) const noexcept
{
  MDB_ASSERT(abbrev_sec->GetName() == ".debug_abbrev",
    "Wrong ELF section was used, expected .debug_abbrev but received {}",
    abbrev_sec->GetName());
  return abbrev_sec->GetPointer(mAbbreviationSectionOffset);
}

const u8 *
UnitHeader::Data() const noexcept
{
  return mDieData.data();
}

const u8 *
UnitHeader::EndExclusive() const noexcept
{
  return mDieData.data() + mDieData.size();
}

Offset
UnitHeader::DebugInfoSectionOffset() const noexcept
{
  return mSecOffset;
}

u8
UnitHeader::Format() const noexcept
{
  return mDwarfFormat;
}

u8
UnitHeader::HeaderLen() const noexcept
{
  const auto fmt = Format();
  MDB_ASSERT(fmt == 4 || fmt == 8, "Unknown format");
  switch (mUnitType) {
  case DwarfUnitType::DW_UT_type:
    return fmt == 4 ? (4 * 6) : (4 * 10);
  case DwarfUnitType::DW_UT_compile:
    [[fallthrough]];
  case DwarfUnitType::DW_UT_partial: {
    return 4 * (3 * (fmt / 4)) - ((std::to_underlying(mDwarfVersion) < 5) ? 1 : 0);
  }
  default:
    MDB_ASSERT(false, "UNIT TYPE {} not yet implemented support for unit at {}", to_str(mUnitType), mSecOffset);
    break;
  }
}

std::span<const u8>
UnitHeader::GetDieData() const noexcept
{
  return mDieData;
}

bool
UnitHeader::SpansAcross(u64 offset) const noexcept
{
  return offset >= mSecOffset && offset <= (mSecOffset + mUnitSize);
}

SymbolInfoId
UnitHeader::UnitId() const noexcept
{
  return mId;
}

DwarfVersion
UnitHeader::Version() const noexcept
{
  return mDwarfVersion;
}

DwarfUnitType
UnitHeader::GetUnitType() const noexcept
{
  return mUnitType;
}

u64
UnitHeader::CompilationUnitSize() const noexcept
{
  return mUnitSize;
}

u64
UnitHeader::TypeSignature() const noexcept
{
  return mTypeSignature;
}

u64
UnitHeader::GetTypeOffset() const noexcept
{
  return mTypeOffset;
}
} // namespace mdb::sym::dw