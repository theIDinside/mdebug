#pragma once
#include "utils/indexing.h"
#include <optional>
#include <symbolication/dwarf_defs.h>

struct AttributeValue;

namespace sym::dw {
class UnitData;
struct DieMetaData;

struct IndexedDieReference;

struct DieReference
{
  UnitData *cu;
  const DieMetaData *die;
  bool valid() const noexcept;
  IndexedDieReference as_indexed() const noexcept;
  std::optional<AttributeValue> read_attribute(Attribute attr) const noexcept;
};

struct IndexedDieReference
{
  UnitData *cu;
  Index die_index;

  bool valid() const noexcept;
  const DieMetaData *get_die() noexcept;

  friend constexpr auto
  operator==(const auto &lhs, const auto &rhs)
  {
    return lhs.cu == rhs.cu && lhs.die_index == rhs.die_index;
  }
};

} // namespace sym::dw