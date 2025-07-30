/** LICENSE TEMPLATE */
#pragma once
#include "utils/indexing.h"
#include <common/typedefs.h>
#include <span>
#include <symbolication/dwarf/common.h>
#include <symbolication/dwarf_defs.h>
namespace mdb {
struct ElfSection;
}

namespace mdb::sym::dw {

class UnitHeader
{
public:
  // Partial/Compile Unit-header constructor
  UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data, u64 abbrev_offset,
             u8 addr_size, u8 format, DwarfVersion version, DwarfUnitType unit_type) noexcept;

  // Type Unit-Header constructor
  UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data, u64 abbrev_offset,
             u8 addr_size, u8 format, u64 type_signature, u64 type_offset) noexcept;

  UnitHeader(const UnitHeader &) = default;
  UnitHeader &operator=(const UnitHeader &) = default;
  UnitHeader(UnitHeader &&) = default;
  UnitHeader &operator=(UnitHeader &&) = default;

  u8 OffsetSize() const noexcept;
  u8 AddrSize() const noexcept;
  const u8 *AbbreviationData(const ElfSection *abbrev_sec) const noexcept;
  const u8 *Data() const noexcept;
  const u8 *EndExclusive() const noexcept;
  Offset DebugInfoSectionOffset() const noexcept;
  u8 Format() const noexcept;
  u8 HeaderLen() const noexcept;
  std::span<const u8> GetDieData() const noexcept;
  bool SpansAcross(u64 sec_offset) const noexcept;
  SymbolInfoId UnitId() const noexcept;
  DwarfVersion Version() const noexcept;
  DwarfUnitType GetUnitType() const noexcept;
  u64 CompilationUnitSize() const noexcept;
  u64 TypeSignature() const noexcept;
  u64 GetTypeOffset() const noexcept;

private:
  Offset mSecOffset;
  u64 mUnitSize;
  std::span<const u8> mDieData;
  u64 mAbbreviationSectionOffset;
  u8 mAddrSize;
  u8 mDwarfFormat;
  DwarfVersion mDwarfVersion;
  DwarfUnitType mUnitType;
  SymbolInfoId mId;
  u64 mTypeSignature{0};
  u64 mTypeOffset{0};
};
} // namespace mdb::sym::dw