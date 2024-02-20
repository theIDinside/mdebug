#include "type.h"
#include "common.h"
#include "dwarf.h"
#include "dwarf_defs.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/die_iterator.h"
#include "symbolication/dwarf_expressions.h"
#include "utils/byte_buffer.h"
#include "utils/enumerator.h"
#include "utils/expected.h"
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
  const auto type_count = types.size();
  for (const auto [k, ptr] : types) {
    delete ptr;
  }
  // Special types void is ok to destroy, because we created them without DWARF. (void, unit type)
  if (type_count > 1)
    PANIC("We don't support unloading Object files during debug session yet - this would introduce all kinds of "
          "weird behaviors and break (current) assumptions about life times.");
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
  ASSERT(array_die.die->has_children, "expected die {} to have children", array_die);

  for (const auto child : sym::dw::IterateSiblings{array_die.cu, array_die.die->children()}) {
    if (child.tag == DwarfTag::DW_TAG_subrange_type) {
      const sym::dw::DieReference ref{.cu = array_die.cu, .die = &child};
      auto bounds = ref.read_attribute(Attribute::DW_AT_count);
      ASSERT(bounds, "{}: Could not determine array type 'subrange count'", ref);
      return bounds->unsigned_value();
    }
  }
  return 0;
}

sym::Type *
TypeStorage::get_or_prepare_new_type(sym::dw::IndexedDieReference die_ref) noexcept
{
  const sym::dw::DieReference this_ref{.cu = die_ref.cu, .die = die_ref.get_die()};
  const auto type_id = this_ref.die->section_offset;
  if (types.contains(type_id)) {
    auto t = types[type_id];
    return t;
  }

  if (is_not_complete_type_die(this_ref.die)) {
    const auto attr = this_ref.read_attribute(Attribute::DW_AT_type);
    auto base_type =
        attr.transform([](auto v) { return v.unsigned_value(); })
            .and_then([&](auto offset) { return die_ref.cu->get_objfile()->get_die_reference(offset); })
            .transform([this](auto other_cu_die) { return get_or_prepare_new_type(other_cu_die.as_indexed()); })
            .or_else([this]() -> std::optional<sym::Type *> { return get_unit_type(); })
            .value();
    auto size = 0u;
    auto array_bounds = 0u;
    // TODO(simon): We only support 64-bit machines right now. Therefore all non-value types/reference-like types
    // are 8 bytes large
    if (sym::is_reference_like(this_ref.die) || base_type->is_reference()) {
      if (this_ref.die->tag == DwarfTag::DW_TAG_array_type) {
        array_bounds = resolve_array_bounds(this_ref);
      }
      size = REFERENCE_SIZE;
    } else {
      size = base_type->size();
    }
    auto type = new sym::Type{die_ref, size, base_type, this_ref.die->tag == DwarfTag::DW_TAG_typedef};
    type->set_array_bounds(array_bounds);
    types[this_ref.die->section_offset] = type;
    return type;
  } else {
    // lambdas have no assigned type name in DWARF (C++). That's just nutter butter shit.
    // Like come on dog. Give it a bogus name, whatever really. But nothing?
    const auto name = this_ref.read_attribute(Attribute::DW_AT_name)
                          .transform([](auto v) { return v.string(); })
                          .value_or("lambda");
    const u32 sz = this_ref.read_attribute(Attribute::DW_AT_byte_size)->unsigned_value();
    auto type = new sym::Type{die_ref, sz, name};
    types[this_ref.die->section_offset] = type;
    return type;
  }
}

sym::Type *
TypeStorage::emplace_type(Offset type_id, sym::dw::IndexedDieReference die_ref, u32 type_size,
                          std::string_view name) noexcept
{
  auto pair = types.emplace(type_id, new sym::Type{die_ref, type_size, name});
  if (pair.second) {
    return pair.first->second;
  }
  return nullptr;
}

namespace sym {

Type::Type(dw::IndexedDieReference die_ref, u32 size_of, Type *target, bool is_typedef) noexcept
    : name(target->name), cu_die_ref(die_ref), modifier{to_type_modifier_will_panic(die_ref.get_die()->tag)},
      size_of(size_of), type_chain(target), fields(), base_type(), is_typedef(is_typedef), resolved(false),
      processing(false)
{
}

Type::Type(dw::IndexedDieReference die_ref, u32 size_of, std::string_view name) noexcept
    : name(name), cu_die_ref(die_ref), modifier{to_type_modifier_will_panic(die_ref.get_die()->tag)},
      size_of(size_of), type_chain(nullptr), fields(), base_type(), is_typedef(false), resolved(false),
      processing(false)
{
}

Type::Type(std::string_view name) noexcept
    : name(name), cu_die_ref(), modifier(Modifier::None), size_of(0), type_chain(nullptr), fields(), base_type(),
      is_typedef(false), resolved(true), processing(false)
{
}

Type::Type(Type &&o) noexcept
    : name(o.name), cu_die_ref(o.cu_die_ref), modifier(o.modifier), size_of(o.size_of), type_chain(o.type_chain),
      fields(std::move(o.fields)), base_type(o.base_type), resolved(o.resolved), processing(o.processing)
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

NonNullPtr<const Type>
Type::target_type() const noexcept
{
  if (type_chain == nullptr)
    return NonNull(*this);
  auto t = type_chain;
  while (t->type_chain) {
    t = t->type_chain;
  }
  return NonNull<const Type>(*t);
}

bool
Type::is_reference() const noexcept
{
  auto mod = std::to_underlying(*modifier);
  constexpr auto ReferenceEnd = std::to_underlying(Modifier::Atomic);
  constexpr auto ReferenceStart = std::to_underlying(Modifier::None);
  if (mod < ReferenceEnd && mod > ReferenceStart)
    return true;
  if (type_chain == nullptr)
    return false;
  auto t = type_chain;
  while (t->type_chain) {
    const auto mod = std::to_underlying(*t->modifier);
    if (mod < ReferenceEnd && mod > ReferenceStart)
      return true;
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
  if (base_type.has_value())
    return true;

  if (is_reference())
    return false;

  auto it = type_chain;
  while (it != nullptr) {
    if (it->base_type.has_value())
      return true;
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
  return this->modifier == Modifier::Array;
}

u32
Type::members_count() const noexcept
{
  ASSERT(resolved, "Type is not fully resolved!");
  return target_type()->fields.size();
}

const std::vector<Field> &
Type::member_variables() const noexcept
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
  auto it = type_chain;
  while (it != nullptr) {
    if (it->modifier == Modifier::None) {
      return it;
    }
    it = it->type_chain;
  }
  return nullptr;
}

void
Type::set_array_bounds(u32 bounds) noexcept
{
  array_bounds = bounds;
}

Value::Value(std::string_view name, Symbol &kind, u32 mem_contents_offset,
             std::shared_ptr<MemoryContentsObject> &&value_object) noexcept
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

Value::Value(std::string &&name, Type &type, u32 mem_contents_offset,
             std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name(std::move(name)), mem_contents_offset(mem_contents_offset), value_origin(&type),
      value_object(std::move(value_object))
{
}

Value::~Value() noexcept { DLOG("mdb", "Destroying value {}", name); }

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

utils::Expected<AddrPtr, ValueError>
Value::to_remote_pointer() noexcept
{
  const auto bytes = memory_view();
  if (bytes.size_bytes() != 8) {
    return utils::unexpected(ValueError::InvalidSize);
  }
  std::uintptr_t ptr{};
  std::memcpy(&ptr, bytes.data(), 8);
  return AddrPtr{ptr};
}

void
Value::set_resolver(std::unique_ptr<ValueResolver> &&res) noexcept
{
  resolver = std::move(res);
}

ValueResolver *
Value::get_resolver() noexcept
{
  return resolver.get();
}
bool
Value::has_visualizer() const noexcept
{
  return visualizer != nullptr;
}

ValueVisualizer *
Value::get_visualizer() noexcept
{
  return visualizer.get();
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

std::span<const u8>
Value::full_memory_view() const noexcept
{
  return value_object->raw_view();
}

MemoryContentsObject::MemoryContentsObject(AddrPtr start, AddrPtr end) noexcept : start(start), end(end) {}

EagerMemoryContentsObject::EagerMemoryContentsObject(AddrPtr start, AddrPtr end,
                                                     MemoryContentBytes &&data) noexcept
    : MemoryContentsObject(start, end), bytes(std::move(data))
{
}

LazyMemoryContentsObject::LazyMemoryContentsObject(TraceeController &supervisor, AddrPtr start,
                                                   AddrPtr end) noexcept
    : MemoryContentsObject(start, end), supervisor(supervisor)
{
}

std::span<const u8>
EagerMemoryContentsObject::raw_view() noexcept
{
  return bytes->span();
}

std::span<const u8>
EagerMemoryContentsObject::view(u32 offset, u32 size) noexcept
{
  return bytes->span().subspan(offset, size);
}

void
LazyMemoryContentsObject::cache_memory() noexcept
{
  DLOG("mdb", "[lazy transfer]: {} .. {}", start, end);
  if (auto res = supervisor.safe_read(start, end->get() - start->get()); res.is_expected()) {
    bytes = std::move(res.take_value());
  } else {
    bytes = std::move(res.take_error().bytes);
  }
}

std::span<const u8>
LazyMemoryContentsObject::raw_view() noexcept
{
  if (bytes == nullptr)
    cache_memory();

  return bytes->span();
}

std::span<const u8>
LazyMemoryContentsObject::view(u32 offset, u32 size) noexcept
{
  if (bytes == nullptr)
    cache_memory();

  return bytes->span().subspan(offset, size);
}

/*static*/
MemoryContentsObject::ReadResult
MemoryContentsObject::read_memory(TraceeController &tc, AddrPtr address, u32 size_of) noexcept
{
  if (auto res = tc.safe_read(address, size_of); res.is_expected()) {
    return ReadResult{.info = ReadResultInfo::Success, .value = res.take_value()};
  } else {
    const auto read_bytes = size_of - res.error().unread_bytes;
    if (read_bytes != 0) {
      return ReadResult{.info = ReadResultInfo::Partial, .value = std::move(res.take_error().bytes)};
    } else {
      return ReadResult{.info = ReadResultInfo::Failed, .value = std::move(res.take_error().bytes)};
    }
  }
}

/*static*/
SharedPtr<Value>
MemoryContentsObject::create_frame_variable(TraceeController &tc, NonNullPtr<TaskInfo> task,
                                            NonNullPtr<sym::Frame> frame, Symbol &symbol, bool lazy) noexcept
{
  const auto requested_byte_size = symbol.type->size();

  switch (symbol.location->kind) {
  case LocKind::DwarfExpression: {
    auto interp = ExprByteCodeInterpreter{frame->level(), tc, task, symbol.location->dwarf_expr};
    const auto address = interp.run();
    if (lazy) {
      auto memory_object = std::make_shared<LazyMemoryContentsObject>(tc, address, address + requested_byte_size);
      return std::make_shared<Value>(symbol.name, symbol, 0, std::move(memory_object));
    } else {
      auto res = tc.safe_read(address, requested_byte_size);
      if (!res.is_expected()) {
        PANIC("Expected read to succeed");
      }
      auto memory_object =
          std::make_shared<EagerMemoryContentsObject>(address, address + requested_byte_size, res.take_value());
      return std::make_shared<Value>(symbol.name, symbol, 0, std::move(memory_object));
    }
  }
  case LocKind::AbsoluteAddress:
    TODO("Is LocKind::AbsoluteAddress really going to be a thing? Absolute address is only really useful "
         "together "
         "with sym::Type, not Symbol.");
    break;
  case LocKind::OffsetOf:
    PANIC("creating a frame variable with LocKind == OffsetOf not allowed");
    break;
  }
  return nullptr;
}

} // namespace sym