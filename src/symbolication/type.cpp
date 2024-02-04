#include "type.h"
#include "common.h"
#include "dwarf.h"
#include "dwarf_defs.h"
#include "symbolication/dwarf_expressions.h"
#include "utils/immutable.h"
#include <supervisor.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/objfile.h>

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
sym::is_reference_like(sym::Type::Modifier modifier) noexcept
{
  switch (modifier) {
  case Type::Modifier::Pointer:
  case Type::Modifier::Reference:
  case Type::Modifier::RValueReference:
    return true;
  case Type::Modifier::None:
  case Type::Modifier::Atomic:
  case Type::Modifier::Const:
  case Type::Modifier::Immutable:
  case Type::Modifier::Packed:
  case Type::Modifier::Restrict:
  case Type::Modifier::Shared:
  case Type::Modifier::Volatile:
    return false;
  }
}

sym::Type::Modifier
sym::to_type_modifier_will_panic(DwarfTag tag) noexcept
{
  switch (tag) {
  case DwarfTag::DW_TAG_atomic_type:
    return sym::Type::Modifier::Atomic;
  case DwarfTag::DW_TAG_const_type:
    return sym::Type::Modifier::Const;
  case DwarfTag::DW_TAG_immutable_type:
    return sym::Type::Modifier::Immutable;
  case DwarfTag::DW_TAG_packed_type:
    return sym::Type::Modifier::Packed;
  case DwarfTag::DW_TAG_pointer_type:
    return sym::Type::Modifier::Pointer;
  case DwarfTag::DW_TAG_reference_type:
    return sym::Type::Modifier::Reference;
  case DwarfTag::DW_TAG_restrict_type:
    return sym::Type::Modifier::Restrict;
  case DwarfTag::DW_TAG_rvalue_reference_type:
    return sym::Type::Modifier::RValueReference;
  case DwarfTag::DW_TAG_shared_type:
    return sym::Type::Modifier::Shared;
  case DwarfTag::DW_TAG_volatile_type:
    return sym::Type::Modifier::Volatile;
  case DwarfTag::DW_TAG_base_type:
  case DwarfTag::DW_TAG_class_type:
  case DwarfTag::DW_TAG_structure_type:
  case DwarfTag::DW_TAG_enumeration_type:
  case DwarfTag::DW_TAG_union_type:
    return sym::Type::Modifier::None;
  default:
    break;
  }
  PANIC(fmt::format("DwarfTag not convertable to Type::Modifier: {}", to_str(tag)));
}

TypeStorage::TypeStorage() noexcept : m(), types() {}

TypeStorage::~TypeStorage() noexcept
{
  const auto type_count = types.size();
  for (const auto [k, ptr] : types) {
    delete ptr;
  }
  if (type_count > 0)
    PANIC("We don't support unloading Object files during debug session yet - this would introduce all kinds of "
          "weird behaviors and break (current) assumptions about life times.");
}

static constexpr auto REFERENCE_SIZE = 8u;

sym::Type *
TypeStorage::get_or_prepare_new_type(sym::dw::IndexedDieReference die_ref) noexcept
{
  const auto this_die = die_ref.get_die();
  const auto type_id = this_die->section_offset;
  if (types.contains(type_id)) {
    auto t = types[type_id];
    return t;
  }

  if (is_not_complete_type_die(this_die)) {
    const auto attr = sym::dw::read_specific_attribute(die_ref.cu, die_ref.get_die(), Attribute::DW_AT_type);
    const auto containing_cu = die_ref.cu->get_objfile()->get_cu_from_offset(attr->unsigned_value());
    const auto die = containing_cu->get_die(attr->unsigned_value());
    auto base_type =
        get_or_prepare_new_type(sym::dw::IndexedDieReference{containing_cu, containing_cu->index_of(die)});
    auto size = 0u;

    // TODO(simon): We only support 64-bit machines right now. Therefore all non-value types/reference-like types
    // are 8 bytes large
    if (sym::is_reference_like(this_die) || base_type->is_reference()) {
      size = REFERENCE_SIZE;
    } else {
      size = base_type->size();
    }
    auto type = new sym::Type{this, die_ref, size, base_type};
    types[this_die->section_offset] = type;
    return type;
  } else {
    const auto name = sym::dw::read_specific_attribute(die_ref.cu, this_die, Attribute::DW_AT_name);
    ASSERT(name, "Expected die 0x{:x} to have a name attribute in it's abbreviation declaration.",
           die_ref.get_die()->section_offset);
    const u32 sz =
        sym::dw::read_specific_attribute(die_ref.cu, this_die, Attribute::DW_AT_byte_size)->unsigned_value();
    auto type = new sym::Type{this, die_ref, sz, name->string()};
    types[this_die->section_offset] = type;
    return type;
  }
}

sym::Type *
TypeStorage::emplace_type(Offset type_id, sym::dw::IndexedDieReference die_ref, u32 type_size,
                          std::string_view name) noexcept
{
  auto pair = types.emplace(type_id, new sym::Type{this, die_ref, type_size, name});
  if (pair.second) {
    return pair.first->second;
  }
  return nullptr;
}

std::mutex &
TypeStorage::get_mutex() noexcept
{
  return m;
}

namespace sym {

Type::Type(TypeStorage *ts, dw::IndexedDieReference die_ref, u32 size_of, Type *target) noexcept
    : owner(ts), name(target->name), cu_die_ref(die_ref),
      modifier{to_type_modifier_will_panic(die_ref.get_die()->tag)}, size_of(size_of), type_chain(target),
      fields(), base_type(), resolved(false), processing(false)
{
}

Type::Type(TypeStorage *ts, dw::IndexedDieReference die_ref, u32 size_of, std::string_view name) noexcept
    : owner(ts), name(name), cu_die_ref(die_ref), modifier{to_type_modifier_will_panic(die_ref.get_die()->tag)},
      size_of(size_of), type_chain(nullptr), fields(), base_type(), resolved(false), processing(false)
{
}

Type::Type(Type &&o) noexcept
    : owner(o.owner), name(o.name), cu_die_ref(o.cu_die_ref), modifier(o.modifier), size_of(o.size_of),
      type_chain(o.type_chain), fields(std::move(o.fields)), base_type(o.base_type), resolved(o.resolved),
      processing(o.processing)
{
  ASSERT(!processing, "Moving a type that's being processed is guaranteed to have undefined behavior");
}

void
Type::add_field(std::string_view name, u64 offset_of, dw::DieReference ref) noexcept
{
  TODO_FMT("implement add_field for {} offset of {}, cu=0x{:x}", name, offset_of, ref.cu->section_offset());
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
  if (type_chain == nullptr)
    return NonNull(*this);
  auto t = type_chain;
  while (t->type_chain) {
    t = t->type_chain;
  }
  return NonNull(*t);
}

bool
Type::is_reference() const noexcept
{
  u8 mod = (u8)(*modifier);
  if (mod < 4 && mod > 0)
    return true;
  if (type_chain == nullptr)
    return false;
  auto t = type_chain;
  while (t->type_chain) {
    mod = (u8)*t->modifier;
    if (mod < 4 && mod > 0)
      return true;
    t = t->type_chain;
  }
  return false;
}

bool
Type::is_resolved() const noexcept
{
  return resolved;
}

u32
Type::size() const noexcept
{
  return size_of;
}

bool
Type::is_primitive() const noexcept
{
  return base_type.has_value();
}

const std::vector<Field> &
Type::member_variables() const noexcept
{
  ASSERT(resolved, "Type is not fully resolved!");
  return fields;
}

Value::Value(std::string_view name, Symbol &kind, u32 mem_contents_offset,
             std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name(name), mem_contents_offset(mem_contents_offset), value_origin(&kind),
      value_object(std::move(value_object))
{
}

Value::Value(std::string_view member_name, Field &kind, u32 containing_structure_offset,
             std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name(member_name), mem_contents_offset(containing_structure_offset + kind.offset_of), value_origin(&kind),
      value_object(std::move(value_object))
{
}

Value::Value(Type &type, u32 mem_contents_offset, std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name("value"), mem_contents_offset(mem_contents_offset), value_origin(&type),
      value_object(std::move(value_object))
{
}

AddrPtr
Value::address() const noexcept
{
  const auto result = value_object->start + mem_contents_offset;
  return result;
}

Type *
Value::type() const noexcept
{
  switch (value_origin.kind) {
  case ValueDescriptor::Kind::Symbol:
    return value_origin.symbol->type;
  case ValueDescriptor::Kind::Field:
    return value_origin.field->type;
  case ValueDescriptor::Kind::AbsoluteAddress:
    return value_origin.type;
  }
}

SharedPtr<MemoryContentsObject>
Value::take_memory_reference() noexcept
{
  return value_object;
}

std::span<const u8>
Value::memory_view() const noexcept
{
  return value_object->view(mem_contents_offset, this->type()->size());
}

MemoryContentsObject::MemoryContentsObject(AddrPtr start, AddrPtr end, MemoryContentBytes &&data) noexcept
    : bytes(std::move(data)), start(start), end(end)
{
}

std::span<const u8>
MemoryContentsObject::view(u32 offset, u32 size) const noexcept
{
  return std::span<const u8>{*bytes}.subspan(offset, size);
}

/*static*/
SharedPtr<Value>
MemoryContentsObject::create_frame_variable(TraceeController &tc, NonNullPtr<TaskInfo> task,
                                            NonNullPtr<sym::Frame> frame, Symbol &symbol) noexcept
{
  const auto requested_byte_size = symbol.type->size();

  switch (symbol.location->kind) {
  case LocKind::DwarfExpression: {
    auto interp = ExprByteCodeInterpreter{frame->level(), tc, task, symbol.location->dwarf_expr};
    const auto address = interp.run();
    auto memory_object = std::make_shared<MemoryContentsObject>(address, address + requested_byte_size,
                                                                tc.read_to_vec(address, requested_byte_size));
    return std::make_shared<Value>(symbol.name, symbol, 0, std::move(memory_object));
  }
  case LocKind::AbsoluteAddress:
    TODO("Is LocKind::AbsoluteAddress really going to be a thing? Absolute address is only really useful together "
         "with sym::Type, not Symbol.");
    break;
  case LocKind::OffsetOf:
    PANIC("creating a frame variable with LocKind == OffsetOf not allowed");
    break;
  }
  return nullptr;
}

} // namespace sym