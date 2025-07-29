/** LICENSE TEMPLATE */
#pragma once
#include <symbolication/dwarf_defs.h>
#include <typedefs.h>
#include <vector>

namespace mdb::sym::dw {
class UnitData;
}
namespace mdb {
class Elf;
struct ElfSection;
struct AddressRange;
} // namespace mdb

namespace mdb::sym::dw {
struct RangeListHeader
{
  static constexpr auto StaticHeaderSize = 10;
  u32 mSectionOffset;
  u64 mInitLength;
  u8 mInitLengthLength;
  DwarfVersion mVersion;
  u8 mAddrSize;
  u8 mSegmentSelectorSize;
  u32 mOffsetEntryCount;
  u32 FirstEntryOffset() const noexcept;
  u32 NextHeaderOffset() const noexcept;
};

struct ResolvedRangeListOffset
{
  u64 mOffset;
  static ResolvedRangeListOffset Make(sym::dw::UnitData &cu, u64 unresolvedOffset) noexcept;
};

AddressRange ReadBoundaries(const ElfSection *rnglists, const RangeListHeader &header) noexcept;
AddressRange ReadBoundaries(const ElfSection *rnglists, const u64 offset) noexcept;
std::vector<AddressRange> ReadBoundaries(sym::dw::UnitData &cu, ResolvedRangeListOffset offset) noexcept;
} // namespace mdb::sym::dw