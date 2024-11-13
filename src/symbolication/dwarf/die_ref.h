#pragma once
#include "utils/indexing.h"
#include <optional>
#include <symbolication/dwarf_defs.h>

struct AttributeValue;

namespace sym::dw {
class UnitData;
struct DieMetaData;
class UnitReader;

/**
 * Reads the following data from the unit die for the compilation unit `compilationUnit`:
 * - The offset to the line number program header
 * - The build directory for this compilation unit
 * This data is not required in Dwarf 5, since the required data is "inlined" into the line number program header,
 * thankfully.
 */
std::tuple<u64, const char *> PrepareCompileUnitDwarf4(UnitData *compilationUnit, const DieMetaData &unitDie);

class IndexedDieReference;

class DieReference
{
protected:
  UnitData *mUnitData;
  const DieMetaData *mDebugInfoEntry;

public:
  DieReference(UnitData *compilationUnit, const DieMetaData *die) noexcept;
  UnitData *GetUnitData() const noexcept;
  const DieMetaData *GetDie() const noexcept;
  DieReference MaybeResolveReference() const noexcept;
  Index IndexOfDie() const noexcept;

  bool IsValid() const noexcept;
  IndexedDieReference AsIndexed() const noexcept;
  std::optional<AttributeValue> read_attribute(Attribute attr) const noexcept;
  UnitReader GetReader() const noexcept;
};

class IndexedDieReference
{
  UnitData *mUnitData;
  Index mDieIndex;

public:
  IndexedDieReference() = default;
  explicit IndexedDieReference(const DieReference &reference) noexcept;
  IndexedDieReference(UnitData *compilationUnit, Index index) noexcept;

  bool IsValid() const noexcept;
  UnitData *GetUnitData() const noexcept;
  Index Index() const noexcept;
  const DieMetaData *GetDie() noexcept;

  friend constexpr auto
  operator==(const auto &lhs, const auto &rhs)
  {
    return lhs.mUnitData == rhs.mUnitData && lhs.mDieIndex == rhs.mDieIndex;
  }
};

} // namespace sym::dw