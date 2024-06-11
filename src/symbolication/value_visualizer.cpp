#include "value_visualizer.h"
#include "common.h"
#include "symbolication/dwarf/typeread.h"
#include "type.h"
#include "utils/enumerator.h"
#include "value.h"
#include <algorithm>
#include <bits/ranges_util.h>
#include <iterator>
#include <supervisor.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/objfile.h>

namespace sym {

ValueResolver::ValueResolver(SymbolFile *object_file, std::weak_ptr<sym::Value> val, TypePtr type) noexcept
    : type(type), obj(object_file), value_ptr(std::move(val)), children()
{
}

Value *
ValueResolver::value() noexcept
{
  if (auto locked = value_ptr.lock(); locked) {
    return locked.get();
  } else {
    return nullptr;
  }
}

std::optional<Children>
ValueResolver::has_cached(std::optional<u32>, std::optional<u32>) noexcept
{
  if (cached) {
    return children;
  }
  return std::nullopt;
}

Children
ValueResolver::resolve(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (const auto res = has_cached(start, count); res) {
    return res.value();
  }

  return get_children(tc, start, count);
}

ReferenceResolver::ReferenceResolver(SymbolFile *obj, std::weak_ptr<sym::Value> val, TypePtr type) noexcept
    : ValueResolver(obj, std::move(val), type)
{
}

Children
ReferenceResolver::get_children(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  auto locked = value_ptr.lock();
  if (!locked) {
    children.clear();
    return children;
  }
  if (const auto address = locked->to_remote_pointer(); address.is_expected()) {
    auto adjusted_address = address.value() + (start.value_or(0) * locked->type()->size());
    const auto requested_length = count.value_or(32);
    auto memory = sym::MemoryContentsObject::read_memory(tc, adjusted_address, requested_length);
    if (!memory.is_ok()) {
      auto t = locked->type()->get_layout_type();
      children.push_back(
        sym::Value::WithVisualizer<sym::InvalidValueVisualizer>(std::make_shared<sym::Value>(*t, 0, nullptr)));
      return children;
    }
    indirect_value_object = std::make_shared<EagerMemoryContentsObject>(
      adjusted_address, adjusted_address + memory.value->size(), std::move(memory.value));

    // actual `T` type behind the reference
    auto layout_type = locked->type()->get_layout_type();

    if (layout_type->is_array_type()) {
      children.push_back(sym::Value::WithVisualizer<sym::ArrayVisualizer>(
        std::make_shared<sym::Value>(*layout_type, 0, indirect_value_object)));
    } else if (layout_type->is_primitive() || layout_type->is_reference()) {
      children.push_back(sym::Value::WithVisualizer<sym::PrimitiveVisualizer>(
        std::make_shared<sym::Value>(*layout_type, 0, indirect_value_object)));
    } else {
      children.push_back(sym::Value::WithVisualizer<sym::DefaultStructVisualizer>(
        std::make_shared<sym::Value>(*layout_type, 0, indirect_value_object)));
    }
  }
  cached = true;
  return children;
}

CStringResolver::CStringResolver(SymbolFile *object_file, std::weak_ptr<sym::Value> val, TypePtr type) noexcept
    : ValueResolver(object_file, std::move(val), type)
{
}

Children
CStringResolver::get_children(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  auto locked = value_ptr.lock();
  if (!locked) {
    children.clear();
    return children;
  }

  if (const auto address = locked->to_remote_pointer(); address.is_expected()) {
    auto adjusted_address = address.value() + (start.value_or(0) * locked->type()->size());
    const auto requested_length = count.value_or(32);
    auto memory = sym::MemoryContentsObject::read_memory(tc, adjusted_address, requested_length);
    indirect_value_object = std::make_shared<EagerMemoryContentsObject>(
      adjusted_address, adjusted_address + memory.value->size(), std::move(memory.value));

    auto span = indirect_value_object->view(0, requested_length);
    for (const auto [index, ch] : utils::EnumerateView(span)) {
      if (ch == 0) {
        null_terminator = index.i;
        break;
      }
    }
    // actual `char` type
    auto layout_type = locked->type()->get_layout_type();
    auto string_value = Value::WithVisualizer<CStringVisualizer>(
      std::make_shared<sym::Value>(*layout_type, 0, indirect_value_object), null_terminator);

    children.push_back(string_value);
  }
  cached = true;
  return children;
}

ArrayResolver::ArrayResolver(SymbolFile *object_file, TypePtr type, u32 array_size,
                             AddrPtr remote_base_addr) noexcept
    : ValueResolver(object_file, {}, type), base_addr(remote_base_addr), element_count(array_size),
      layout_type(type->get_layout_type())
{
}

Children
ArrayResolver::get_all(TraceeController &) noexcept
{
  TODO("ArrayResolver::get_all not implemented");
  return children;
}

std::optional<Children>
ArrayResolver::has_cached(std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (!start) {
    return (children.size() == element_count) ? std::optional{std::span{children}} : std::nullopt;
  }

  const auto start_index = start.value();
  const auto addr_base = address_of(start_index);
  auto iter =
    std::find_if(children.begin(), children.end(), [&](const auto &v) { return v->address() == addr_base; });

  if (iter == std::end(children)) {
    return std::nullopt;
  }

  const u32 iter_index = std::distance(children.begin(), iter);
  if (children.size() - iter_index < count.value()) {
    return std::nullopt;
  }
  const auto e = count.value() + iter_index;
  for (auto i = iter_index + 1; i < e; ++i) {
    auto this_addr = address_of(i);
    if (children[i]->address() != this_addr) {
      return std::nullopt;
    }
  }

  return std::span{children}.subspan(iter_index, count.value());
}

AddrPtr
ArrayResolver::address_of(u32 index) noexcept
{
  return base_addr + (index * layout_type->size());
}

Children
ArrayResolver::get_children(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (!start) {
    return get_all(tc);
  }

  if (start.value() + count.value_or(0) > element_count) {
    return {};
  }

  const u32 s = start.value();
  const u32 e = s + std::min(count.value_or(100), element_count);

  auto addr_base = base_addr + (s * layout_type->size());

  auto start_insert_at = std::find_if(children.begin(), children.end(), [&](auto &v) {
    const auto cmp = v->address();
    if (cmp == addr_base) {
      return true;
    }
    return cmp > addr_base;
  });

  if (start_insert_at == end(children)) {
    const auto idx = children.size();
    const u32 type_sz = layout_type->size_of;
    for (auto i = 0u; i < (e - s); ++i) {
      const auto current_address = addr_base + (type_sz * i);
      auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, current_address, current_address + type_sz);
      children.emplace_back(std::make_shared<Value>(std::to_string(s + i), *layout_type, 0, lazy));
    }

    return std::span{children.begin() + idx, children.end()};
  } else {
    const u32 idx = std::distance(children.begin(), start_insert_at);
    u32 i = 0u;
    const u32 total = std::min(count.value_or(100), element_count - idx);
    auto iter = start_insert_at;
    const u32 type_sz = layout_type->size_of;
    while (i < total) {
      auto current_address = addr_base + (type_sz * i);
      if (iter == std::end(children)) {
        auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, current_address, current_address + type_sz);
        iter = children.insert(iter, std::make_shared<Value>(std::to_string(s + i), *layout_type, 0, lazy));
      } else if ((*iter)->address() != current_address) {
        auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, current_address, current_address + type_sz);
        iter = children.insert(iter, std::make_shared<Value>(std::to_string(s + i), *layout_type, 0, lazy));
      }
      ++iter;
      ++i;
    }
    const auto span_start = children.begin() + idx;
    const auto span_end = span_start + total;
    return std::span{span_start, span_end};
  }
}

ValueVisualizer::ValueVisualizer(std::weak_ptr<Value> provider) noexcept : data_provider(provider) {}

std::optional<std::string>
PrimitiveVisualizer::format_enum(Type &t, std::span<const u8> span) noexcept
{
  auto &enums = t.enumerations();
  EnumeratorConstValue value;
  if (enums.is_signed) {
    switch (t.size_of) {
    case 1:
      value.i = bit_copy<i8>(span);
      break;
    case 2:
      value.i = bit_copy<i16>(span);
      break;
    case 4:
      value.i = bit_copy<i32>(span);
      break;
    case 8:
      value.i = bit_copy<i64>(span);
      break;
    }
  } else {
    switch (t.size_of) {
    case 1:
      value.u = bit_copy<u8>(span);
      break;
    case 2:
      value.u = bit_copy<u16>(span);
      break;
    case 4:
      value.u = bit_copy<u32>(span);
      break;
    case 8:
      value.u = bit_copy<u64>(span);
      break;
    }
  }

  const auto &fields = t.member_variables();
  if (enums.is_signed) {
    for (auto i = 0u; i < fields.size(); ++i) {
      if (enums.e_values[i].i == value.i) {
        return fmt::format("{}::{}", t.name, fields[i].name);
      }
    }
    return fmt::format("{}::(invalid){}", t.name, value.i);
  } else {
    for (auto i = 0u; i < fields.size(); ++i) {
      if (enums.e_values[i].u == value.u) {
        return fmt::format("{}::{}", t.name, fields[i].name);
      }
    }
    return fmt::format("{}::(invalid){}", t.name, value.u);
  }
}

PrimitiveVisualizer::PrimitiveVisualizer(std::weak_ptr<Value> provider) noexcept : ValueVisualizer(provider) {}
// TODO(simon): add optimization where we can format our value directly to an outbuf?
std::optional<std::string>
PrimitiveVisualizer::format_value() noexcept
{
  auto ptr = data_provider.lock();
  if (!ptr) {
    return std::nullopt;
  }

  const auto span = ptr->memory_view();
  if (span.empty()) {
    return std::nullopt;
  }
  auto type = ptr->type();
  const auto size_of = type->size_of;

  if (type->is_reference()) {
    const std::uintptr_t ptr = bit_copy<std::uintptr_t>(span);
    return fmt::format("0x{:x}", ptr);
  }

  auto target_type = type->target_type();
  if (target_type->tag() == DwarfTag::DW_TAG_enumeration_type) {
    if (!target_type->is_resolved()) {
      dw::TypeSymbolicationContext ctx{*target_type->cu_die_ref->cu->get_objfile(), *target_type.ptr};
      ctx.resolve_type();
    }

    return format_enum(*target_type, span);
  }

  switch (type->get_base_type().value()) {
  case BaseTypeEncoding::DW_ATE_address: {
    std::uintptr_t value = bit_copy<std::uintptr_t>(span);
    return fmt::format("0x{}", value);
  }
  case BaseTypeEncoding::DW_ATE_boolean: {
    bool value = bit_copy<bool>(span);
    return fmt::format("{}", value);
  }
  case BaseTypeEncoding::DW_ATE_float: {
    if (size_of == 4u) {
      float value = bit_copy<float>(span);
      return fmt::format("{}", value);
    } else if (size_of == 8u) {
      double value = bit_copy<double>(span);
      return fmt::format("{}", value);
    } else {
      PANIC("Expected byte size of a floating point to be 4 or 8");
    }
  }
  case BaseTypeEncoding::DW_ATE_signed_char:
  case BaseTypeEncoding::DW_ATE_signed:
    switch (size_of) {
    case 1: {
      signed char value = bit_copy<signed char>(span);
      return fmt::format("{}", value);
    }
    case 2: {
      signed short value = bit_copy<signed short>(span);
      return fmt::format("{}", value);
    }
    case 4: {
      int value = bit_copy<int>(span);
      return fmt::format("{}", value);
    }
    case 8: {
      signed long long value = bit_copy<signed long long>(span);
      return fmt::format("{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_unsigned_char:
  case BaseTypeEncoding::DW_ATE_unsigned:
    switch (size_of) {
    case 1: {
      u8 value = bit_copy<unsigned char>(span);
      return fmt::format("{}", value);
    }
    case 2: {
      u16 value = bit_copy<unsigned short>(span);
      return fmt::format("{}", value);
    }
    case 4: {
      u32 value = bit_copy<u32>(span);
      return fmt::format("{}", value);
    }
    case 8: {
      u64 value = bit_copy<u64>(span);
      return fmt::format("{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_UTF: {
    u32 value = bit_copy<u32>(span);
    return fmt::format("{}", value);
  } break;
  case BaseTypeEncoding::DW_ATE_ASCII:
  case BaseTypeEncoding::DW_ATE_edited:
  case BaseTypeEncoding::DW_ATE_signed_fixed:
  case BaseTypeEncoding::DW_ATE_unsigned_fixed:
  case BaseTypeEncoding::DW_ATE_decimal_float:
  case BaseTypeEncoding::DW_ATE_imaginary_float:
  case BaseTypeEncoding::DW_ATE_packed_decimal:
  case BaseTypeEncoding::DW_ATE_numeric_string:
  case BaseTypeEncoding::DW_ATE_complex_float:

  case BaseTypeEncoding::DW_ATE_UCS: {
    TODO_FMT("Currently not implemented base type encoding: {}", to_str(type->get_base_type().value()));
    break;
  }
  case BaseTypeEncoding::DW_ATE_lo_user:
  case BaseTypeEncoding::DW_ATE_hi_user:
    break;
  }
  PANIC("unknown base type encoding");
}

std::optional<std::string>
PrimitiveVisualizer::dap_format(std::string_view name, int variablesReference) noexcept
{
  auto ptr = data_provider.lock();
  if (!ptr) {
    return std::nullopt;
  }
  ASSERT(name == ptr->name, "variable name {} != provided name {}", ptr->name, name);
  const auto byte_span = ptr->memory_view();
  if (byte_span.empty()) {
    return std::nullopt;
  }

  auto value_field = format_value().value_or("could not serialize value");

  return fmt::format(
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }})", name,
    value_field, (*ptr->type()), variablesReference, ptr->address());
}

DefaultStructVisualizer::DefaultStructVisualizer(std::weak_ptr<Value> value) noexcept : ValueVisualizer(value) {}
// TODO(simon): add optimization where we can format our value directly to an outbuf?
std::optional<std::string>
DefaultStructVisualizer::format_value() noexcept
{
  TODO("not done");
}

std::optional<std::string>
DefaultStructVisualizer::dap_format(std::string_view name, int variablesReference) noexcept
{
  auto ptr = data_provider.lock();
  if (!ptr) {
    return std::nullopt;
  }

  ASSERT(name == ptr->name, "variable name {} != provided name {}", ptr->name, name);
  const auto &t = *ptr->type();
  return fmt::format(
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }})", name,
    t, t, variablesReference, ptr->address());
}

InvalidValueVisualizer::InvalidValueVisualizer(std::weak_ptr<Value> provider_with_no_value) noexcept
    : ValueVisualizer(std::move(provider_with_no_value))
{
}

std::optional<std::string>
InvalidValueVisualizer::format_value() noexcept
{
  TODO("InvalidValueVisualizer::format_value() not yet implemented");
}

std::optional<std::string>
InvalidValueVisualizer::dap_format(std::string_view name, int variablesReference) noexcept
{
  auto ptr = this->data_provider.lock();
  return fmt::format(
    R"({{ "name": "{}", "value": "could not resolve {}", "type": "{}", "variablesReference": 0 }})", ptr->name,
    ptr->name, *ptr->type());
}

ArrayVisualizer::ArrayVisualizer(std::weak_ptr<Value> provider) noexcept : ValueVisualizer(provider) {}

std::optional<std::string>
ArrayVisualizer::format_value() noexcept
{
  TODO("not impl");
}
std::optional<std::string>
ArrayVisualizer::dap_format(std::string_view, int variablesReference) noexcept
{
  auto ptr = this->data_provider.lock();
  if (!ptr) {
    return std::nullopt;
  }

  auto &t = *ptr->type();
  const auto no_alias = t.resolve_alias();
  return fmt::format(
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}", "indexedVariables": {} }})",
    ptr->name, t, t, variablesReference, ptr->address(), no_alias->array_size());
}

CStringVisualizer::CStringVisualizer(std::weak_ptr<Value> data_provider,
                                     std::optional<u32> null_terminator) noexcept
    : ValueVisualizer(data_provider), null_terminator(null_terminator)
{
}

std::optional<std::string>
CStringVisualizer::format_value() noexcept
{
  auto ptr = this->data_provider.lock();
  if (!ptr) {
    return std::nullopt;
  }
  const auto byte_span = ptr->full_memory_view();
  if (byte_span.empty()) {
    return std::nullopt;
  }
  std::string_view cast{(const char *)byte_span.data(), null_terminator.value_or(byte_span.size_bytes())};
  return fmt::format("{}", cast);
}

std::optional<std::string>
CStringVisualizer::dap_format(std::string_view name, int) noexcept
{
  auto ptr = this->data_provider.lock();
  if (!ptr) {
    return std::nullopt;
  }
  const auto byte_span = ptr->full_memory_view();
  if (byte_span.empty()) {
    return std::nullopt;
  }

  std::string_view cast{(const char *)byte_span.data(), null_terminator.value_or(byte_span.size_bytes())};

  return fmt::format(
    R"({{ "name": "{}", "value": "{}", "type": "const char *", "variablesReference": {}, "memoryReference": "{}" }})",
    name, cast, 0, ptr->address());
}
} // namespace sym