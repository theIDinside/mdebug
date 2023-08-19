#include "type.h"
#include "dwarf.h"
#include "dwarf_defs.h"

namespace sym {
Type::Type(std::string_view name) noexcept
    : name(name), size_of(0), base_type(BaseTypeEncoding::DW_ATE_hi_user), type_code(TypeEncoding::BaseType),
      fields()
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

TypeReader::TypeReader(u64 dbg_inf_start_offs, TypeMap &storage, const DebugInfoEntry *type) noexcept
    : dbg_inf_start_offs(dbg_inf_start_offs), storage(storage), root(type)
{
  curr_stack.push(root);
}

auto
TypeReader::read_in() noexcept -> void
{
  switch (current()->tag) {
  case DwarfTag::DW_TAG_class_type:
  case DwarfTag::DW_TAG_structure_type:
  case DwarfTag::DW_TAG_union_type:
  case DwarfTag::DW_TAG_interface_type:
    DLOG("dwarf", "[read_in]: die=0x{:x}, structured", current()->sec_offset);
    return read_structured();
  case DwarfTag::DW_TAG_base_type:
    DLOG("dwarf", "[read_in]: die=0x{:x}, base_type", current()->sec_offset);
    return read_primitive();
  case DwarfTag::DW_TAG_array_type:
  case DwarfTag::DW_TAG_enumeration_type:
  case DwarfTag::DW_TAG_pointer_type:
  case DwarfTag::DW_TAG_reference_type:
  case DwarfTag::DW_TAG_string_type:
  case DwarfTag::DW_TAG_typedef:
  case DwarfTag::DW_TAG_variant:
  case DwarfTag::DW_TAG_subrange_type:
  case DwarfTag::DW_TAG_generic_subrange:
  case DwarfTag::DW_TAG_ptr_to_member_type:
  case DwarfTag::DW_TAG_set_type:
  case DwarfTag::DW_TAG_packed_type:
  case DwarfTag::DW_TAG_volatile_type:
  case DwarfTag::DW_TAG_restrict_type:
  case DwarfTag::DW_TAG_unspecified_type:
  case DwarfTag::DW_TAG_rvalue_reference_type:
  case DwarfTag::DW_TAG_coarray_type:
  case DwarfTag::DW_TAG_dynamic_type:
  case DwarfTag::DW_TAG_atomic_type:
  case DwarfTag::DW_TAG_shared_type:
    break;
  case DwarfTag::DW_TAG_subroutine_type:
  case DwarfTag::DW_TAG_inlined_subroutine:
  case DwarfTag::DW_TAG_subprogram:
    TODO_FMT("mdb", "do we really expect a subprogram, subroutine or inlined subroutine here? ({})",
             to_str(root->tag));
    break;
  case DwarfTag::DW_TAG_const_type:
    DLOG("mdb", "{} not supported type to parse yet", to_str(root->tag));
    break;
  default:
    TODO_FMT("reading type with TAG {} not supported", to_str(root->tag));
  }
}

auto
TypeReader::current() noexcept -> const DebugInfoEntry *
{
  return curr_stack.top();
}

auto
TypeReader::read_type_from_signature() noexcept -> void
{
}

auto
TypeReader::read_structured() noexcept -> void
{
  const auto die_key = sec_offset(current());
  if (storage.contains(die_key))
    return;

  if (const auto sig = current()->get_attribute(Attribute::DW_AT_signature); sig) {
    return read_type_from_signature();
  }

  auto name =
      current()->get_attribute(Attribute::DW_AT_name).transform([](const auto &attr) { return attr.string(); });
  ASSERT(name.has_value(), "Type must have a DW_AT_name for now");

  storage.emplace(std::make_pair(die_key, Type{*name}));
  auto &type = storage.at(die_key);
  type.set_type_code(TypeEncoding::Structure);
  type.resolved = false;
  type.size_of = current()->get_attribute(Attribute::DW_AT_byte_size)->unsigned_value();
  for (const auto &child : current()->children) {
    const auto name = child->get_attribute(Attribute::DW_AT_name)->string();
    curr_stack.push(child.get());
    read_in();
    curr_stack.pop();
    auto offset = child->get_attribute(Attribute::DW_AT_data_member_location)->unsigned_value();
    switch (child->tag) {
    case DwarfTag::DW_TAG_member:
      type.fields.push_back(Field{.name = name,
                                  .offset_of = offset,
                                  .field_index = type.fields.size(),
                                  .type = &storage.at(sec_offset(child.get()))});
      break;
    case DwarfTag::DW_TAG_template_type_parameter:
      break;
    case DwarfTag::DW_TAG_inheritance:
      break;
    case DwarfTag::DW_TAG_subprogram:
      break;
    default:
      break;
    }
  }
}

auto
TypeReader::read_primitive() noexcept -> void
{
  if (storage.contains(sec_offset(current())))
    return;
  auto name =
      current()->get_attribute(Attribute::DW_AT_name).transform([](const auto &attr) { return attr.string(); });
  ASSERT(name.has_value(), "Type must have a DW_AT_name for now");
  storage.emplace(std::make_pair(current()->sec_offset, Type{*name}));
  auto &type = storage.at(current()->sec_offset);
  type.set_type_code(TypeEncoding::BaseType);
  type.resolved = true;
  type.size_of = current()->get_attribute(Attribute::DW_AT_byte_size)->unsigned_value();
}

auto
TypeReader::sec_offset(const DebugInfoEntry *ent) noexcept -> u64
{
  return ent->sec_offset - dbg_inf_start_offs;
}

} // namespace sym