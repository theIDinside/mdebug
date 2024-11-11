#include "type.h"
#include "common.h"
#include "dwarf.h"
#include "dwarf_defs.h"
#include "symbolication/dwarf/attribute_read.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/die_iterator.h"
#include "symbolication/dwarf/die_ref.h"
#include "utils/immutable.h"
#include <optional>
#include <supervisor.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/objfile.h>
#include <utility>

static constexpr bool
is_not_complete_type_die(const sym::dw::DieMetaData *die)
{
  switch (die->tag) {
  case DwarfTag::DW_TAG_pointer_type:
  case DwarfTag::DW_TAG_reference_type:
  case DwarfTag::DW_TAG_const_type:
  case DwarfTag::DW_TAG_volatile_type:
  case DwarfTag::DW_TAG_rvalue_reference_type:
  case DwarfTag::DW_TAG_array_type:
  case DwarfTag::DW_TAG_typedef:
    return true;
  default:
    return false;
  }
}

bool
sym::is_reference_like(const dw::DieMetaData *die) noexcept
{
  return is_reference_like(to_type_modifier_will_panic(die->tag));
}

bool
sym::is_reference_like(sym::Modifier modifier) noexcept
{
  switch (modifier) {
  case Modifier::Pointer:
  case Modifier::Reference:
  case Modifier::RValueReference:
  case Modifier::Array:
    return true;
  case Modifier::None:
  case Modifier::Atomic:
  case Modifier::Const:
  case Modifier::Immutable:
  case Modifier::Packed:
  case Modifier::Restrict:
  case Modifier::Shared:
  case Modifier::Volatile:
    return false;
  }
  NEVER("Unknown modifier");
}

sym::Modifier
sym::to_type_modifier_will_panic(DwarfTag tag) noexcept
{
  switch (tag) {
  case DwarfTag::DW_TAG_array_type:
    return sym::Modifier::Array;
  case DwarfTag::DW_TAG_atomic_type:
    return sym::Modifier::Atomic;
  case DwarfTag::DW_TAG_const_type:
    return sym::Modifier::Const;
  case DwarfTag::DW_TAG_immutable_type:
    return sym::Modifier::Immutable;
  case DwarfTag::DW_TAG_packed_type:
    return sym::Modifier::Packed;
  case DwarfTag::DW_TAG_pointer_type:
    return sym::Modifier::Pointer;
  case DwarfTag::DW_TAG_reference_type:
    return sym::Modifier::Reference;
  case DwarfTag::DW_TAG_restrict_type:
    return sym::Modifier::Restrict;
  case DwarfTag::DW_TAG_rvalue_reference_type:
    return sym::Modifier::RValueReference;
  case DwarfTag::DW_TAG_shared_type:
    return sym::Modifier::Shared;
  case DwarfTag::DW_TAG_volatile_type:
    return sym::Modifier::Volatile;
  case DwarfTag::DW_TAG_base_type:
  case DwarfTag::DW_TAG_class_type:
  case DwarfTag::DW_TAG_structure_type:
  case DwarfTag::DW_TAG_enumeration_type:
  case DwarfTag::DW_TAG_union_type:
  case DwarfTag::DW_TAG_typedef:
    return sym::Modifier::None;
  default:
    break;
  }
  PANIC(fmt::format("DwarfTag not convertable to Type::Modifier: {}", to_str(tag)));
}

TypeStorage::TypeStorage(ObjectFile &obj) noexcept : m(), types(), obj(obj) { types[0] = new sym::Type{"void"}; }

TypeStorage::~TypeStorage() noexcept
{
  DBGLOG(core, "Destroying type storage for {}", obj.path->c_str());
  for (const auto [k, ptr] : types) {
    delete ptr;
  }
}

static constexpr auto REFERENCE_SIZE = 8u;

sym::Type *
TypeStorage::get_unit_type() noexcept
{
  return types[0];
}

static u32
resolve_array_bounds(sym::dw::DieReference array_die) noexcept
{
  ASSERT(array_die.GetDie()->has_children, "expected die {} to have children", array_die);

  for (const auto child : sym::dw::IterateSiblings{array_die.GetUnitData(), array_die.GetDie()->children()}) {
    if (child.tag == DwarfTag::DW_TAG_subrange_type) {
      const sym::dw::DieReference ref{array_die.GetUnitData(), &child};
      u64 count{};
      sym::dw::ProcessDie(ref, [&](sym::dw::UnitReader& reader, sym::dw::Abbreviation& attr, const auto& info) {
        switch(attr.name) {
          case Attribute::DW_AT_count: [[fallthrough]];
            count = sym::dw::read_attribute_value(reader, attr, info.implicit_consts).unsigned_value();
            return sym::dw::DieAttributeRead::Done;
          case Attribute::DW_AT_upper_bound:
            count = sym::dw::read_attribute_value(reader, attr, info.implicit_consts).unsigned_value() + 1;
            return sym::dw::DieAttributeRead::Done;
          default:
            return sym::dw::DieAttributeRead::Continue;
        }
      });
      return count;
    }
  }
  return 0;
}

sym::Type *
TypeStorage::get_or_prepare_new_type(sym::dw::IndexedDieReference die_ref) noexcept
{
  const sym::dw::DieReference this_ref{die_ref.GetUnitData(), die_ref.GetDie()};
  const auto type_id = this_ref.GetDie()->section_offset;

  if (types.contains(type_id)) {
    auto t = types[type_id];
    return t;
  }

  if (is_not_complete_type_die(this_ref.GetDie())) {
    const auto attr = this_ref.read_attribute(Attribute::DW_AT_type);
    auto base_type =
      attr.transform([](auto v) { return v.unsigned_value(); })
        .and_then([&](auto offset) { return die_ref.GetUnitData()->get_objfile()->get_die_reference(offset); })
        .transform([this](auto other_cu_die) { return get_or_prepare_new_type(other_cu_die.AsIndexed()); })
        .or_else([this]() -> std::optional<sym::Type *> { return get_unit_type(); })
        .value();
    auto size = 0u;
    auto array_bounds = 0u;
    // TODO(simon): We only support 64-bit machines right now. Therefore all non-value types/reference-like types
    // are 8 bytes large
    if (sym::is_reference_like(this_ref.GetDie()) || base_type->is_reference()) {
      if (this_ref.GetDie()->tag == DwarfTag::DW_TAG_array_type) {
        array_bounds = resolve_array_bounds(this_ref);
      }
      size = REFERENCE_SIZE;
    } else {
      size = base_type->size();
    }

    auto type =
      new sym::Type{this_ref.GetDie()->tag, die_ref, size, base_type, this_ref.GetDie()->tag == DwarfTag::DW_TAG_typedef};
    type->set_array_bounds(array_bounds);
    types[this_ref.GetDie()->section_offset] = type;
    return type;
  } else {
    if (const auto &attr_val = this_ref.read_attribute(Attribute::DW_AT_signature); attr_val) {
      // DWARF5 support; we might run into type units, therefore we have to resolve the *actual* die we want here
      // yet we still want to map this_ref's die offset to the type. This is unfortunate, since we might get
      // "copies" i.e. mulitple die's that have a ref signature. The actual backing data is just 1 of though, so it
      // just means mulitple keys can reach the value, which is a pointer to the actual type.
      auto tu_die_ref = this_ref.GetUnitData()->get_objfile()->get_type_unit_type_die(attr_val->unsigned_value());
      ASSERT(tu_die_ref.IsValid(), "expected die reference to type unit to be valid");
      const u32 sz = tu_die_ref.read_attribute(Attribute::DW_AT_byte_size)->unsigned_value();
      const auto name = tu_die_ref.read_attribute(Attribute::DW_AT_name)
                          .transform(AttributeValue::as_string)
                          .value_or("<no name>");
      auto type = new sym::Type{this_ref.GetDie()->tag, tu_die_ref.AsIndexed(), sz, name};
      types[this_ref.GetDie()->section_offset] = type;
      return type;
    } else {
      // lambdas have no assigned type name in DWARF (C++). That's just nutter butter shit.
      // Like come on dog. Give it a bogus name, whatever really. But nothing?
      const auto name = this_ref.read_attribute(Attribute::DW_AT_name)
                          .transform([](auto v) { return v.string(); })
                          .value_or("lambda");
      const u32 sz = this_ref.read_attribute(Attribute::DW_AT_byte_size)->unsigned_value();
      auto type = new sym::Type{this_ref.GetDie()->tag, die_ref, sz, name};
      types[this_ref.GetDie()->section_offset] = type;
      return type;
    }
  }
}

sym::Type *
TypeStorage::emplace_type(DwarfTag tag, Offset type_id, sym::dw::IndexedDieReference die_ref, u32 type_size,
                          std::string_view name) noexcept
{
  auto pair = types.emplace(type_id, new sym::Type{tag, die_ref, type_size, name});
  if (pair.second) {
    return pair.first->second;
  }
  return nullptr;
}

namespace sym {

Type::Type(DwarfTag die_tag, dw::IndexedDieReference die_ref, u32 size_of, Type *target, bool is_typedef) noexcept
    : name(target->name), cu_die_ref(die_ref), modifier{to_type_modifier_will_panic(die_ref.GetDie()->tag)},
      is_typedef(is_typedef), resolved(false), processing(false), size_of(size_of), type_chain(target), fields(),
      base_type(), die_tag(die_tag)
{
}

Type::Type(DwarfTag die_tag, dw::IndexedDieReference die_ref, u32 size_of, std::string_view name) noexcept
    : name(name), cu_die_ref(die_ref), modifier{to_type_modifier_will_panic(die_ref.GetDie()->tag)},
      is_typedef(false), resolved(false), processing(false), size_of(size_of), type_chain(nullptr), fields(),
      base_type(), die_tag(die_tag)
{
}

Type::Type(std::string_view name) noexcept
    : name(name), cu_die_ref(), modifier(Modifier::None), is_typedef(false), resolved(true), processing(false),
      size_of(0), type_chain(nullptr), fields(), base_type()
{
}

Type::Type(Type &&o) noexcept
    : name(o.name), cu_die_ref(o.cu_die_ref), modifier(o.modifier), resolved(o.resolved), processing(o.processing),
      size_of(o.size_of), type_chain(o.type_chain), fields(std::move(o.fields)), base_type(o.base_type)
{
  ASSERT(!processing, "Moving a type that's being processed is guaranteed to have undefined behavior");
}

Type *
Type::resolve_alias() noexcept
{
  if (!is_typedef) {
    return this;
  }
  auto t = type_chain;
  while (t && t->is_typedef) {
    t = t->type_chain;
  }
  return t;
}

void
Type::add_field(std::string_view name, u64 offset_of, dw::DieReference ref) noexcept
{
  TODO_FMT("implement add_field for {} offset of {}, cu=0x{:x}", name, offset_of, ref.GetUnitData()->section_offset());
  // fields.emplace_back(name, offset_of, Immutable<Offset>{ref.die->section_offset});
}

void
Type::set_base_type_encoding(BaseTypeEncoding enc) noexcept
{
  base_type = enc;
}

NonNullPtr<Type>
Type::target_type() noexcept
{
  if (type_chain == nullptr) {
    return NonNull(*this);
  }
  auto t = type_chain;
  while (t->type_chain) {
    t = t->type_chain;
  }
  return NonNull<Type>(*t);
}

bool
Type::is_reference() const noexcept
{
  auto mod = std::to_underlying(*modifier);
  constexpr auto ReferenceEnd = std::to_underlying(Modifier::Atomic);
  constexpr auto ReferenceStart = std::to_underlying(Modifier::None);
  if (mod < ReferenceEnd && mod > ReferenceStart) {
    return true;
  }
  if (type_chain == nullptr) {
    return false;
  }
  auto t = type_chain;
  while (t) {
    const auto mod = std::to_underlying(*t->modifier);
    if (mod < ReferenceEnd && mod > ReferenceStart) {
      return true;
    }
    t = t->type_chain;
  }
  return false;
}

bool
Type::is_resolved() const noexcept
{
  if (is_typedef) {
    return type_chain->resolved;
  }
  return resolved;
}

u32
Type::size() noexcept
{
  return size_of;
}

u32
Type::size_bytes() noexcept
{
  if (modifier == Modifier::Array) {
    auto bounds = size();
    auto layout_type_size = get_layout_type()->size();
    return bounds * layout_type_size;
  } else {
    return size();
  }
}

bool
Type::is_primitive() const noexcept
{
  if (base_type.has_value() || die_tag == DwarfTag::DW_TAG_enumeration_type) {
    return true;
  }

  if (is_reference()) {
    return false;
  }

  auto it = type_chain;
  while (it != nullptr) {
    if (it->base_type.has_value() || it->die_tag == DwarfTag::DW_TAG_enumeration_type) {
      return true;
    }
    it = it->type_chain;
  }
  return false;
}

bool
Type::is_char_type() const noexcept
{
  return base_type
    .transform([](auto v) {
      switch (v) {
      case BaseTypeEncoding::DW_ATE_signed_char:
      case BaseTypeEncoding::DW_ATE_unsigned_char:
        return true;
      default:
        return false;
      }
    })
    .value_or(false);
}

bool
Type::is_array_type() const noexcept
{
  if (!is_typedef) {
    return this->modifier == Modifier::Array;
  }
  auto t = type_chain;
  while (t->is_typedef) {
    t = t->type_chain;
  }
  return t->modifier == Modifier::Array;
}

u32
Type::members_count() noexcept
{
  ASSERT(resolved, "Type is not fully resolved!");
  return target_type()->fields.size();
}

const std::vector<Field> &
Type::member_variables() noexcept
{
  ASSERT(resolved, "Type is not fully resolved!");
  auto t = target_type();
  return t->fields;
}

Type *
Type::get_layout_type() noexcept
{
  if (modifier == Modifier::None) {
    return this;
  }

  if (auto t = resolve_alias(); t->is_reference()) {
    t = t == this ? t->type_chain : t;
    while (!t->is_reference() && t->modifier != Modifier::None) {
      t = t->type_chain->resolve_alias();
    }
    return t;
  } else {
    auto it = type_chain;
    while (it != nullptr) {
      if (it->modifier == Modifier::None) {
        return it;
      }
      it = it->type_chain;
    }
  }

  return nullptr;
}

void
Type::set_array_bounds(u32 bounds) noexcept
{
  array_bounds = bounds;
}

} // namespace sym