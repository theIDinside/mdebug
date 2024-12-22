#include "value_visualizer.h"
#include "symbolication/dwarf/typeread.h"
#include "type.h"
#include "utils/enumerator.h"
#include "value.h"
#include <algorithm>
#include <iterator>
#include <memory_resource>
#include <string>
#include <supervisor.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/objfile.h>

namespace sym {

#define FormatAndReturn(result, formatString, ...)                                                                \
  fmt::format_to(std::back_inserter(result), formatString __VA_OPT__(, ) __VA_ARGS__);                            \
  return result

ValueResolver::ValueResolver(SymbolFile *objectFile, std::weak_ptr<sym::Value> val, TypePtr type) noexcept
    : mType(type), mSymbolFile(objectFile), mValuePointer(std::move(val)), mChildren()
{
}

Value *
ValueResolver::GetValue() noexcept
{
  if (auto locked = mValuePointer.lock(); locked) {
    return locked.get();
  } else {
    return nullptr;
  }
}

std::optional<Children>
ValueResolver::HasCached(std::optional<u32>, std::optional<u32>) noexcept
{
  if (mIsCached) {
    return mChildren;
  }
  return std::nullopt;
}

Children
ValueResolver::Resolve(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (const auto res = HasCached(start, count); res) {
    return res.value();
  }

  return GetChildren(tc, start, count);
}

ReferenceResolver::ReferenceResolver(SymbolFile *obj, std::weak_ptr<sym::Value> val, TypePtr type) noexcept
    : ValueResolver(obj, std::move(val), type)
{
}

Children
ReferenceResolver::GetChildren(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  auto locked = mValuePointer.lock();
  if (!locked) {
    mChildren.clear();
    return mChildren;
  }
  if (const auto address = locked->ToRemotePointer(); address.is_expected()) {
    auto adjusted_address = address.value() + (start.value_or(0) * locked->GetType()->Size());
    const auto requested_length = count.value_or(32);
    auto memory = sym::MemoryContentsObject::ReadMemory(tc, adjusted_address, requested_length);
    if (!memory.is_ok()) {
      auto t = locked->GetType()->TypeDescribingLayoutOfThis();
      mChildren.push_back(
        sym::Value::WithVisualizer<sym::InvalidValueVisualizer>(std::make_shared<sym::Value>(*t, 0, nullptr)));
      return mChildren;
    }
    mIndirectValueObject = std::make_shared<EagerMemoryContentsObject>(
      adjusted_address, adjusted_address + memory.value->size(), std::move(memory.value));

    // actual `T` type behind the reference
    auto layout_type = locked->GetType()->TypeDescribingLayoutOfThis();

    if (layout_type->IsArrayType()) {
      mChildren.push_back(sym::Value::WithVisualizer<sym::ArrayVisualizer>(
        std::make_shared<sym::Value>(*layout_type, 0, mIndirectValueObject)));
    } else if (layout_type->IsPrimitive() || layout_type->IsReference()) {
      mChildren.push_back(sym::Value::WithVisualizer<sym::PrimitiveVisualizer>(
        std::make_shared<sym::Value>(*layout_type, 0, mIndirectValueObject)));
    } else {
      mChildren.push_back(sym::Value::WithVisualizer<sym::DefaultStructVisualizer>(
        std::make_shared<sym::Value>(*layout_type, 0, mIndirectValueObject)));
    }
  }
  mIsCached = true;
  return mChildren;
}

CStringResolver::CStringResolver(SymbolFile *objectFile, std::weak_ptr<sym::Value> val, TypePtr type) noexcept
    : ValueResolver(objectFile, std::move(val), type)
{
}

Children
CStringResolver::GetChildren(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  auto locked = mValuePointer.lock();
  if (!locked) {
    mChildren.clear();
    return mChildren;
  }

  if (const auto address = locked->ToRemotePointer(); address.is_expected()) {
    auto adjustedAddress = address.value() + (start.value_or(0) * locked->GetType()->Size());
    const auto requestedLength = count.value_or(256);
    auto referencedMemory = sym::MemoryContentsObject::ReadMemory(tc, adjustedAddress, requestedLength);
    if (!referencedMemory.is_ok()) {
      auto layoutType = locked->GetType()->TypeDescribingLayoutOfThis();
      mChildren.push_back(
        Value::WithVisualizer<InvalidValueVisualizer>(std::make_shared<sym::Value>(*layoutType, 0, nullptr)));
      return mChildren;
    }
    mIndirectValueObject = std::make_shared<EagerMemoryContentsObject>(
      adjustedAddress, adjustedAddress + referencedMemory.value->size(), std::move(referencedMemory.value));

    auto span = mIndirectValueObject->View(0, requestedLength);
    for (const auto [index, ch] : utils::EnumerateView(span)) {
      if (ch == 0) {
        mNullTerminatorPosition = index.i;
        break;
      }
    }
    // actual `char` type
    auto layout_type = locked->GetType()->TypeDescribingLayoutOfThis();
    auto string_value = Value::WithVisualizer<CStringVisualizer>(
      std::make_shared<sym::Value>(*layout_type, 0, mIndirectValueObject), mNullTerminatorPosition);

    mChildren.push_back(string_value);
  }
  mIsCached = true;
  return mChildren;
}

ArrayResolver::ArrayResolver(SymbolFile *objectFile, TypePtr type, u32 arraySize,
                             AddrPtr remoteBaseAddress) noexcept
    : ValueResolver(objectFile, {}, type), mBaseAddress(remoteBaseAddress), mElementCount(arraySize),
      mLayoutType(type->TypeDescribingLayoutOfThis())
{
}

Children
ArrayResolver::get_all(TraceeController &) noexcept
{
  TODO("ArrayResolver::get_all not implemented");
  return mChildren;
}

std::optional<Children>
ArrayResolver::HasCached(std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (!start) {
    return (mChildren.size() == mElementCount) ? std::optional{std::span{mChildren}} : std::nullopt;
  }

  const auto start_index = start.value();
  const auto addr_base = AddressOf(start_index);
  auto iter =
    std::find_if(mChildren.begin(), mChildren.end(), [&](const auto &v) { return v->Address() == addr_base; });

  if (iter == std::end(mChildren)) {
    return std::nullopt;
  }

  const u32 iter_index = std::distance(mChildren.begin(), iter);
  if (mChildren.size() - iter_index < count.value()) {
    return std::nullopt;
  }
  const auto e = count.value() + iter_index;
  for (auto i = iter_index + 1; i < e; ++i) {
    auto this_addr = AddressOf(i);
    if (mChildren[i]->Address() != this_addr) {
      return std::nullopt;
    }
  }

  return std::span{mChildren}.subspan(iter_index, count.value());
}

AddrPtr
ArrayResolver::AddressOf(u32 index) noexcept
{
  return mBaseAddress + (index * mLayoutType->Size());
}

Children
ArrayResolver::GetChildren(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (!start) {
    return get_all(tc);
  }

  if (start.value() + count.value_or(0) > mElementCount) {
    return {};
  }

  const u32 s = start.value();
  const u32 e = s + std::min(count.value_or(100), mElementCount);

  auto addr_base = mBaseAddress + (s * mLayoutType->Size());

  auto start_insert_at = std::find_if(mChildren.begin(), mChildren.end(), [&](auto &v) {
    const auto cmp = v->Address();
    if (cmp == addr_base) {
      return true;
    }
    return cmp > addr_base;
  });

  if (start_insert_at == end(mChildren)) {
    const auto idx = mChildren.size();
    const u32 type_sz = mLayoutType->size_of;
    for (auto i = 0u; i < (e - s); ++i) {
      const auto current_address = addr_base + (type_sz * i);
      auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, current_address, current_address + type_sz);
      mChildren.emplace_back(std::make_shared<Value>(std::to_string(s + i), *mLayoutType, 0, lazy));
    }

    return std::span{mChildren.begin() + idx, mChildren.end()};
  } else {
    const u32 idx = std::distance(mChildren.begin(), start_insert_at);
    u32 i = 0u;
    const u32 total = std::min(count.value_or(100), mElementCount - idx);
    auto iter = start_insert_at;
    const u32 type_sz = mLayoutType->size_of;
    while (i < total) {
      auto current_address = addr_base + (type_sz * i);
      if (iter == std::end(mChildren)) {
        auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, current_address, current_address + type_sz);
        iter = mChildren.insert(iter, std::make_shared<Value>(std::to_string(s + i), *mLayoutType, 0, lazy));
      } else if ((*iter)->Address() != current_address) {
        auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, current_address, current_address + type_sz);
        iter = mChildren.insert(iter, std::make_shared<Value>(std::to_string(s + i), *mLayoutType, 0, lazy));
      }
      ++iter;
      ++i;
    }
    const auto span_start = mChildren.begin() + idx;
    const auto span_end = span_start + total;
    return std::span{span_start, span_end};
  }
}

ValueVisualizer::ValueVisualizer(std::weak_ptr<Value> provider) noexcept
    : mDataProvider(std::move(provider))
{
}

std::optional<std::pmr::string>
PrimitiveVisualizer::FormatEnum(Type &t, std::span<const u8> span, std::pmr::memory_resource* allocator) noexcept
{
  auto &enums = t.GetEnumerations();
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

  const auto &fields = t.MemberFields();
  if (enums.is_signed) {
    for (auto i = 0u; i < fields.size(); ++i) {
      if (enums.e_values[i].i == value.i) {
        std::pmr::string result{allocator};
        FormatAndReturn(result, "{}::{}", t.mName, fields[i].name);
      }
    }
    std::pmr::string result{allocator};
    FormatAndReturn(result, "{}::(invalid){}", t.mName, value.i);
  } else {
    for (auto i = 0u; i < fields.size(); ++i) {
      if (enums.e_values[i].u == value.u) {
        std::pmr::string result{allocator};
        FormatAndReturn(result, "{}::{}", t.mName, fields[i].name);
      }
    }
    std::pmr::string result{allocator};
    FormatAndReturn(result, "{}::(invalid){}", t.mName, value.u);
  }
}

PrimitiveVisualizer::PrimitiveVisualizer(std::weak_ptr<Value> provider) noexcept
    : ValueVisualizer(std::move(provider))
{
}
// TODO(simon): add optimization where we can format our value directly to an outbuf?
std::optional<std::pmr::string>
PrimitiveVisualizer::FormatValue(std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  if (!ptr) {
    return std::nullopt;
  }

  const auto span = ptr->MemoryView();
  if (span.empty()) {
    return std::nullopt;
  }
  auto type = ptr->GetType();
  const auto size_of = type->size_of;

  std::pmr::string result{allocator};

  if (type->IsReference()) {
    const std::uintptr_t ptr = bit_copy<std::uintptr_t>(span);
    FormatAndReturn(result, "0x{:x}", ptr);
  }

  auto target_type = type->GetTargetType();
  if (target_type->GetDwarfTag() == DwarfTag::DW_TAG_enumeration_type) {
    if (!target_type->IsResolved()) {
      dw::TypeSymbolicationContext ctx{*target_type->mCompUnitDieReference->GetUnitData()->GetObjectFile(),
                                       *target_type.ptr};
      ctx.resolve_type();
    }

    return FormatEnum(*target_type, span, allocator);
  }

  switch (type->GetBaseType().value()) {
  case BaseTypeEncoding::DW_ATE_address: {
    std::uintptr_t value = bit_copy<std::uintptr_t>(span);
    FormatAndReturn(result, "0x{}", value);
  }
  case BaseTypeEncoding::DW_ATE_boolean: {
    bool value = bit_copy<bool>(span);
    FormatAndReturn(result, "{}", value);
  }
  case BaseTypeEncoding::DW_ATE_float: {
    if (size_of == 4u) {
      float value = bit_copy<float>(span);
      FormatAndReturn(result, "{}", value);
    } else if (size_of == 8u) {
      double value = bit_copy<double>(span);
      FormatAndReturn(result, "{}", value);
    } else {
      PANIC("Expected byte size of a floating point to be 4 or 8");
    }
  }
  case BaseTypeEncoding::DW_ATE_signed_char:
  case BaseTypeEncoding::DW_ATE_signed:
    switch (size_of) {
    case 1: {
      signed char value = bit_copy<signed char>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 2: {
      signed short value = bit_copy<signed short>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 4: {
      int value = bit_copy<int>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 8: {
      signed long long value = bit_copy<signed long long>(span);
      FormatAndReturn(result, "{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_unsigned_char:
  case BaseTypeEncoding::DW_ATE_unsigned:
    switch (size_of) {
    case 1: {
      u8 value = bit_copy<unsigned char>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 2: {
      u16 value = bit_copy<unsigned short>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 4: {
      u32 value = bit_copy<u32>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 8: {
      u64 value = bit_copy<u64>(span);
      FormatAndReturn(result, "{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_UTF: {
    u32 value = bit_copy<u32>(span);
    FormatAndReturn(result, "{}", value);
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
    TODO_FMT("Currently not implemented base type encoding: {}", to_str(type->GetBaseType().value()));
    break;
  }
  case BaseTypeEncoding::DW_ATE_lo_user:
  case BaseTypeEncoding::DW_ATE_hi_user:
    break;
  }
  PANIC("unknown base type encoding");
}

std::optional<std::pmr::string>
PrimitiveVisualizer::DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  if (!ptr) {
    return std::nullopt;
  }
  ASSERT(name == ptr->mName, "variable name {} != provided name {}", ptr->mName, name);
  const auto byte_span = ptr->MemoryView();
  if (byte_span.empty()) {
    return std::nullopt;
  }

  auto value_field = FormatValue(allocator).value_or(std::pmr::string{"could not serialize value", allocator});
  std::pmr::string result{allocator};

  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }})", name,
    value_field, (*ptr->GetType()), variablesReference, ptr->Address());
}

DefaultStructVisualizer::DefaultStructVisualizer(std::weak_ptr<Value> value) noexcept
    : ValueVisualizer(std::move(value))
{
}
// TODO(simon): add optimization where we can format our value directly to an outbuf?
std::optional<std::pmr::string>
DefaultStructVisualizer::FormatValue(std::pmr::memory_resource* allocator) noexcept
{
  TODO("not done");
}

std::optional<std::pmr::string>
DefaultStructVisualizer::DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  if (!ptr) {
    return std::nullopt;
  }

  ASSERT(name == ptr->mName, "variable name {} != provided name {}", ptr->mName, name);
  const auto &t = *ptr->GetType();
  std::pmr::string result{allocator};
  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }})", name,
    t, t, variablesReference, ptr->Address());
}

InvalidValueVisualizer::InvalidValueVisualizer(std::weak_ptr<Value> providerWithNoValue) noexcept
    : ValueVisualizer(std::move(providerWithNoValue))
{
}

std::optional<std::pmr::string>
InvalidValueVisualizer::FormatValue(std::pmr::memory_resource*) noexcept
{
  TODO("InvalidValueVisualizer::format_value() not yet implemented");
}

std::optional<std::pmr::string>
InvalidValueVisualizer::DapFormat(std::string_view, int, std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  std::pmr::string result{allocator};
  FormatAndReturn(result,
                  R"({{ "name": "{}", "value": "could not resolve {}", "type": "{}", "variablesReference": 0 }})",
                  ptr->mName, ptr->mName, *ptr->GetType());
}

ArrayVisualizer::ArrayVisualizer(std::weak_ptr<Value> provider) noexcept
    : ValueVisualizer(std::move(provider))
{
}

std::optional<std::pmr::string>
ArrayVisualizer::FormatValue(std::pmr::memory_resource*) noexcept
{
  TODO("not impl");
}

std::optional<std::pmr::string>
ArrayVisualizer::DapFormat(std::string_view, int variablesReference, std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  if (!ptr) {
    return std::nullopt;
  }

  auto &t = *ptr->GetType();
  const auto no_alias = t.ResolveAlias();
  std::pmr::string result{allocator};
  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}", "indexedVariables": {} }})",
    ptr->mName, t, t, variablesReference, ptr->Address(), no_alias->ArraySize());
}

CStringVisualizer::CStringVisualizer(std::weak_ptr<Value> dataProvider, std::optional<u32> nullTerminatorPosition) noexcept
    : ValueVisualizer(std::move(dataProvider)), null_terminator(nullTerminatorPosition)
{
}

std::optional<std::pmr::string>
CStringVisualizer::FormatValue(std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  if (!ptr) {
    return std::nullopt;
  }
  const auto byte_span = ptr->FullMemoryView();
  if (byte_span.empty()) {
    return std::nullopt;
  }
  std::string_view cast{(const char *)byte_span.data(), null_terminator.value_or(byte_span.size_bytes())};
  std::pmr::string result{allocator};
  FormatAndReturn(result, "{}", cast);
}

std::optional<std::pmr::string>
CStringVisualizer::DapFormat(std::string_view name, int, std::pmr::memory_resource* allocator) noexcept
{
  auto ptr = mDataProvider.lock();
  if (!ptr) {
    return std::nullopt;
  }
  const auto byte_span = ptr->FullMemoryView();
  if (byte_span.empty()) {
    return std::nullopt;
  }

  std::string_view cast{(const char *)byte_span.data(), null_terminator.value_or(byte_span.size_bytes())};
  std::pmr::string result{allocator};
  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "const char *", "variablesReference": {}, "memoryReference": "{}" }})",
    name, cast, 0, ptr->Address());
}

#undef FormatAndReturn
} // namespace sym