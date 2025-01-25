/** LICENSE TEMPLATE */
#pragma once

#include "symbolication/dwarf.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf_defs.h"
#include <array>
#include <optional>
#include <type_traits>
namespace sym::dw {

template <size_t N>
std::array<std::optional<AttributeValue>, N>
read_attributes(UnitData *unitData, const DieMetaData &die, std::array<Attribute, N> &&attributes)
{
  std::array<std::optional<AttributeValue>, N> result;
  UnitReader reader{unitData};
  const auto &attrs = unitData->GetAbbreviation(die.mAbbreviationCode);
  reader.SeekDie(die);

  for (auto attribute : attrs.mAttributes) {
    for (auto i = 0; i < attributes.size(); ++i) {
      if (attribute.mName == attributes[i]) {
        result[i] = ReadAttributeValue(reader, attribute, attrs.mImplicitConsts);
        goto resume;
      }
    }

    reader.SkipAttribute(attribute);
  resume:
    continue;
  }
  return result;
}

enum class DieAttributeRead
{
  Continue,
  Skipped,
  Done,
};

template <typename Fn>
void
ProcessDie(DieReference dieRef, Fn &&fn) noexcept
{
  static_assert(std::is_same_v<std::invoke_result_t<Fn, UnitReader &, Abbreviation &, const AbbreviationInfo &>,
                               DieAttributeRead>,
                "Requires function to return DieAttributeRead");
  auto unit = dieRef.GetUnitData();
  const auto die = unit ? dieRef.GetDie() : nullptr;
  ASSERT(unit && die, "Compilation Unit required to be not-null");
  UnitReader reader{unit};
  const auto &attrs = unit->GetAbbreviation(die->mAbbreviationCode);
  reader.SeekDie(*die);
  for (auto attribute : attrs.mAttributes) {
    switch (fn(reader, attribute, attrs)) {
    case DieAttributeRead::Continue:
      break;
      ;
    case DieAttributeRead::Skipped:
      reader.SkipAttribute(attribute);
      break;
    case DieAttributeRead::Done:
      return;
    }
  }
}
} // namespace sym::dw