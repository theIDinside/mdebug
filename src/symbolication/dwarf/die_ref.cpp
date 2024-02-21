#include "die_ref.h"
#include "symbolication/dwarf.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include <symbolication/dwarf/die.h>

namespace sym::dw {
bool
DieReference::valid() const noexcept
{
  return cu != nullptr && die != nullptr;
}

bool
IndexedDieReference::valid() const noexcept
{
  return cu != nullptr;
}

IndexedDieReference
DieReference::as_indexed() const noexcept
{
  return IndexedDieReference{.cu = cu, .die_index = cu->index_of(die)};
}

std::optional<AttributeValue>
DieReference::read_attribute(Attribute attr) const noexcept
{
  UnitReader reader{cu};
  const auto &attrs = cu->get_abbreviation(die->abbreviation_code);
  reader.seek_die(*die);
  for (auto attribute : attrs.attributes) {
    const auto value = read_attribute_value(reader, attribute, attrs.implicit_consts);
    if (value.name == attr) {
      return value;
    }
  }
  return std::nullopt;
}

const DieMetaData *
IndexedDieReference::get_die() noexcept
{
  return &cu->get_dies()[die_index.value()];
}
} // namespace sym::dw