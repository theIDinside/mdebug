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
  const auto &attrs = unitData->get_abbreviation(die.abbreviation_code);
  reader.SeekDie(die);

  for (auto attribute : attrs.attributes) {
    for (auto i = 0; i < attributes.size(); ++i) {
      if (attribute.name == attributes[i]) {
        result[i] = read_attribute_value(reader, attribute, attrs.implicit_consts);
        goto resume;
      }
    }

    reader.skip_attribute(attribute);
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
  const auto &attrs = unit->get_abbreviation(die->abbreviation_code);
  reader.SeekDie(*die);
  for (auto attribute : attrs.attributes) {
    switch (fn(reader, attribute, attrs)) {
    case DieAttributeRead::Continue:
      break;
      ;
    case DieAttributeRead::Skipped:
      reader.skip_attribute(attribute);
      break;
    case DieAttributeRead::Done:
      return;
    }
  }
}
} // namespace sym::dw