#include "die.h"

// SYMBOLS DWARF namespace
namespace sym::dw {
void
DebugInfoEntry::debug_dump(int indent) const noexcept
{
  std::string fill(indent, ' ');
  fmt::print("{} [{}] {}\n", fill, abbreviation_code, to_str(this->tag));
  for (const auto &att : attributes) {
    fmt::println("{} | {} {}", fill, to_str(att.name), to_str(att.form));
  }
  fmt::println("---");
  for (const auto &ch : children) {
    ch->debug_dump(indent + 1);
  }
}

void
DebugInfoEntry::set_abbreviation(const AbbreviationInfo &a) noexcept
{
  abbreviation_code = a.code;
  set_tag(a.tag);
}

void
DebugInfoEntry::set_offset(u64 offset) noexcept
{
  sec_offset = offset;
}

std::optional<AttributeValue>
DebugInfoEntry::get_attribute(Attribute attr) const noexcept
{
  for (const auto &att : attributes) {
    if (att.name == attr)
      return att;
  }
  return std::nullopt;
}

std::uintptr_t
AttributeValue::address() const noexcept
{
  return value.addr;
}
std::string_view
AttributeValue::string() const noexcept
{
  return value.str;
}
DataBlock
AttributeValue::block() const noexcept
{
  return value.block;
}
u64
AttributeValue::unsigned_value() const noexcept
{
  return value.u;
}
i64
AttributeValue::signed_value() const noexcept
{
  return value.i;
}

} // namespace sym::dw