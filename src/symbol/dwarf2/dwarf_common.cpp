#include "dwarf_common.h"

namespace sym::dw2 {
DwarfId::DwarfId(u64 uid) noexcept : uid(uid) {}

u64
DwarfId::get_id() const noexcept
{
  return uid;
}

bool
DwarfId::operator<(const DwarfId &other) noexcept
{
  return uid < other.uid;
}
bool
DwarfId::operator==(const DwarfId &other) noexcept
{
  return uid == other.uid;
}
bool
DwarfId::operator>(const DwarfId &other) noexcept
{
  return uid > other.uid;
}
} // namespace sym::dw2