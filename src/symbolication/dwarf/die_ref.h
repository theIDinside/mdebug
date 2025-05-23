/** LICENSE TEMPLATE */
#pragma once
#include <optional>
#include <symbolication/dwarf_defs.h>

namespace mdb {
struct AttributeValue;
}

namespace mdb::sym::dw {
class UnitData;
struct DieMetaData;
class UnitReader;
struct AbbreviationInfo;

/**
 * Reads the following data from the unit die for the compilation unit `compilationUnit`:
 * - The offset to the line number program header
 * - The build directory for this compilation unit
 * This data is not required in Dwarf 5, since the required data is "inlined" into the line number program header,
 * thankfully.
 */
std::tuple<u64, const char *> PrepareCompileUnitPreDwarf5(UnitData *compilationUnit, const DieMetaData &unitDie);

class IndexedDieReference;

class DieReference
{
protected:
  UnitData *mUnitData;
  const DieMetaData *mDebugInfoEntry;

public:
  DieReference() noexcept = default;
  DieReference(UnitData *compilationUnit, const DieMetaData *die) noexcept;
  UnitData *GetUnitData() const noexcept;
  const DieMetaData *GetDie() const noexcept;
  DieReference MaybeResolveReference() const noexcept;
  u64 IndexOfDie() const noexcept;

  const AbbreviationInfo &GetAbbreviation() const noexcept;

  bool IsValid() const noexcept;
  IndexedDieReference AsIndexed() const noexcept;
  std::optional<AttributeValue> ReadAttribute(Attribute attr) const noexcept;
  UnitReader GetReader() const noexcept;
};

class IndexedDieReference
{
  UnitData *mUnitData;
  u64 mDieIndex;

public:
  IndexedDieReference() = default;
  explicit IndexedDieReference(const DieReference &reference) noexcept;
  IndexedDieReference(UnitData *compilationUnit, u64 index) noexcept;

  bool IsValid() const noexcept;
  UnitData *GetUnitData() const noexcept;
  u64 GetIndex() const noexcept;
  const DieMetaData *GetDie() noexcept;

  friend constexpr auto
  operator==(const auto &lhs, const auto &rhs)
  {
    return lhs.mUnitData == rhs.mUnitData && lhs.mDieIndex == rhs.mDieIndex;
  }
};

} // namespace mdb::sym::dw