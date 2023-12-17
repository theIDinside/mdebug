#include "type.h"
#include "dwarf.h"
#include "dwarf_defs.h"
#include "symbolication/dwarf/die.h"

namespace sym {
Type::Type(std::string_view name) noexcept
    : name(name), size_of(0), base_type(BaseTypeEncoding::DW_ATE_hi_user), type_code(TypeEncoding::BaseType),
      fields(), die_ref()
{
}

Type::Type(Type &&o) noexcept
    : name(o.name), size_of(o.size_of), base_type(o.base_type), type_code(o.type_code), fields(std::move(o.fields))
{
}

auto
Type::set_field_count(u32 cnt) noexcept -> void
{
  fields.reserve(cnt);
}

auto
Type::set_field(Field field, u32 index) noexcept -> void
{
  fields[index] = field;
}

auto
Type::set_type_code(TypeEncoding enc) noexcept -> void
{
  type_code = enc;
}

} // namespace sym