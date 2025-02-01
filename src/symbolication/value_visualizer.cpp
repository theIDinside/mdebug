/** LICENSE TEMPLATE */
#include "value_visualizer.h"
#include "symbolication/dwarf/typeread.h"
#include "tracer.h"
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

namespace mdb::sym {

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

std::vector<Ref<Value>>
ResolveReference::Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile,
                          ValueRange valueRange) noexcept
{
  std::vector<Ref<Value>> mResults;

  if (const auto address = value.ToRemotePointer(); address.is_expected()) {
    auto adjusted_address = address.value() + (valueRange.start.value_or(0) * value.GetType()->Size());
    const auto requested_length = valueRange.count.value_or(32);
    auto memory = sym::MemoryContentsObject::ReadMemory(tc, adjusted_address, requested_length);
    if (!memory.is_ok()) {
      auto t = value.GetType()->TypeDescribingLayoutOfThis();
      mResults.push_back(
        Ref<Value>::MakeShared(*t, 0u, nullptr, Tracer::GetSerializer<sym::InvalidValueVisualizer>()));
      return mResults;
    }
    auto mIndirectValueObject = std::make_shared<EagerMemoryContentsObject>(
      adjusted_address, adjusted_address + memory.value->size(), std::move(memory.value));

    // actual `T` type behind the reference
    auto layout_type = value.GetType()->TypeDescribingLayoutOfThis();

    if (layout_type->IsArrayType()) {
      mResults.push_back(Ref<Value>::MakeShared(*layout_type, 0u, mIndirectValueObject,
                                                Tracer::GetSerializer<sym::ArrayVisualizer>()));
    } else if (layout_type->IsPrimitive() || layout_type->IsReference()) {
      mResults.push_back(Ref<Value>::MakeShared(*layout_type, 0u, mIndirectValueObject,
                                                Tracer::GetSerializer<sym::PrimitiveVisualizer>()));
    } else {
      mResults.push_back(Ref<Value>::MakeShared(*layout_type, 0u, mIndirectValueObject,
                                                Tracer::GetSerializer<sym::DefaultStructVisualizer>()));
    }
  }
  return mResults;
}

std::vector<Ref<Value>>
ResolveCString::Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile, ValueRange valueRange) noexcept
{
  std::vector<Ref<Value>> mResults;
  if (const auto address = value.ToRemotePointer(); address.is_expected()) {
    auto adjustedAddress = address.value() + (valueRange.start.value_or(0) * value.GetType()->Size());
    const auto requestedLength = valueRange.count.value_or(256);
    auto referencedMemory = sym::MemoryContentsObject::ReadMemory(tc, adjustedAddress, requestedLength);
    if (!referencedMemory.is_ok()) {
      auto layoutType = value.GetType()->TypeDescribingLayoutOfThis();
      mResults.push_back(
        Ref<Value>::MakeShared(*layoutType, 0u, nullptr, Tracer::GetSerializer<InvalidValueVisualizer>()));
      return mResults;
    }
    auto indirectValueObject = std::make_shared<EagerMemoryContentsObject>(
      adjustedAddress, adjustedAddress + referencedMemory.value->size(), std::move(referencedMemory.value));

    auto span = indirectValueObject->View(0, requestedLength);

    // actual `char` type
    auto layoutType = value.GetType()->TypeDescribingLayoutOfThis();
    auto stringValue = Ref<sym::Value>::MakeShared(*layoutType, 0u, indirectValueObject,
                                                   Tracer::GetSerializer<CStringVisualizer>());

    mResults.push_back(std::move(stringValue));
  }
  return mResults;
}

std::vector<Ref<Value>>
ResolveArray::Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile, ValueRange valueRange) noexcept
{
  ASSERT(value.GetType() && value.GetType()->IsArrayType(), "Expected value-type to be an array-type");
  std::vector<Ref<Value>> mResults;
  const auto arraySize = value.GetType()->ArraySize();
  Type *elementsType = value.GetType()->TypeDescribingLayoutOfThis();

  if (valueRange.start.value() >= arraySize) {
    return {};
  }

  auto count = std::min(valueRange.count.value_or(100), arraySize - valueRange.start.value());

  const u32 startIndex = valueRange.start.value();
  const u32 endIndex = startIndex + count;

  const auto arrayBaseAddress = value.Address();

  const auto desiredFirstElementAddress = arrayBaseAddress + (startIndex * elementsType->size_of);
  const u32 elementTypeSize = elementsType->size_of;
  auto underlying = (endIndex - startIndex) * elementTypeSize;
  // We make backing memory view for the entire sub-range.
  auto lazy = std::make_shared<LazyMemoryContentsObject>(tc, desiredFirstElementAddress,
                                                         desiredFirstElementAddress + underlying);

  for (auto i = 0u; i < (endIndex - startIndex); ++i) {
    const auto current_address = desiredFirstElementAddress + (elementTypeSize * i);
    const auto memoryObjectOffset = i * elementTypeSize;
    mResults.emplace_back(
      Ref<Value>::MakeShared(std::to_string(startIndex + i), *elementsType, memoryObjectOffset, lazy));
  }

  return mResults;
}

std::optional<std::pmr::string>
PrimitiveVisualizer::FormatEnum(Type &t, std::span<const u8> span, std::pmr::memory_resource *allocator) noexcept
{
  auto &enums = t.GetEnumerations();
  EnumeratorConstValue value;
  if (enums.is_signed) {
    switch (t.size_of) {
    case 1:
      value.i = BitCopy<i8>(span);
      break;
    case 2:
      value.i = BitCopy<i16>(span);
      break;
    case 4:
      value.i = BitCopy<i32>(span);
      break;
    case 8:
      value.i = BitCopy<i64>(span);
      break;
    }
  } else {
    switch (t.size_of) {
    case 1:
      value.u = BitCopy<u8>(span);
      break;
    case 2:
      value.u = BitCopy<u16>(span);
      break;
    case 4:
      value.u = BitCopy<u32>(span);
      break;
    case 8:
      value.u = BitCopy<u64>(span);
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

// TODO(simon): add optimization where we can format our value directly to an outbuf?
std::optional<std::pmr::string>
PrimitiveVisualizer::FormatValue(const Value &value, std::pmr::memory_resource *allocator) noexcept
{
  const auto span = value.MemoryView();
  if (span.empty()) {
    return std::nullopt;
  }
  auto type = value.GetType();
  const auto size_of = type->size_of;

  std::pmr::string result{allocator};

  if (type->IsReference()) {
    const std::uintptr_t ptr = BitCopy<std::uintptr_t>(span);
    FormatAndReturn(result, "0x{:x}", ptr);
  }

  auto target_type = type->GetTargetType();
  if (target_type->GetDwarfTag() == DwarfTag::DW_TAG_enumeration_type) {
    if (!target_type->IsResolved()) {
      dw::TypeSymbolicationContext ctx{*target_type->mCompUnitDieReference->GetUnitData()->GetObjectFile(),
                                       *target_type.ptr};
      ctx.ResolveType();
    }

    return FormatEnum(*target_type, span, allocator);
  }

  switch (type->GetBaseType().value()) {
  case BaseTypeEncoding::DW_ATE_address: {
    std::uintptr_t value = BitCopy<std::uintptr_t>(span);
    FormatAndReturn(result, "0x{}", value);
  }
  case BaseTypeEncoding::DW_ATE_boolean: {
    bool value = BitCopy<bool>(span);
    FormatAndReturn(result, "{}", value);
  }
  case BaseTypeEncoding::DW_ATE_float: {
    if (size_of == 4u) {
      float value = BitCopy<float>(span);
      FormatAndReturn(result, "{}", value);
    } else if (size_of == 8u) {
      double value = BitCopy<double>(span);
      FormatAndReturn(result, "{}", value);
    } else {
      PANIC("Expected byte size of a floating point to be 4 or 8");
    }
  }
  case BaseTypeEncoding::DW_ATE_signed_char:
  case BaseTypeEncoding::DW_ATE_signed:
    switch (size_of) {
    case 1: {
      signed char value = BitCopy<signed char>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 2: {
      signed short value = BitCopy<signed short>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 4: {
      int value = BitCopy<int>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 8: {
      signed long long value = BitCopy<signed long long>(span);
      FormatAndReturn(result, "{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_unsigned_char:
  case BaseTypeEncoding::DW_ATE_unsigned:
    switch (size_of) {
    case 1: {
      u8 value = BitCopy<unsigned char>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 2: {
      u16 value = BitCopy<unsigned short>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 4: {
      u32 value = BitCopy<u32>(span);
      FormatAndReturn(result, "{}", value);
    }
    case 8: {
      u64 value = BitCopy<u64>(span);
      FormatAndReturn(result, "{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_UTF: {
    u32 value = BitCopy<u32>(span);
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
PrimitiveVisualizer::Serialize(const Value &value, std::string_view name, int variablesReference,
                               std::pmr::memory_resource *allocator) noexcept
{
  ASSERT(name == value.mName, "variable name {} != provided name {}", value.mName, name);
  const auto byte_span = value.MemoryView();
  if (byte_span.empty()) {
    return std::nullopt;
  }

  auto value_field =
    FormatValue(value, allocator).value_or(std::pmr::string{"could not serialize value", allocator});
  std::pmr::string result{allocator};

  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }})", name,
    value_field, *(value.GetType()), variablesReference, value.Address());
}

std::optional<std::pmr::string>
DefaultStructVisualizer::Serialize(const Value &value, std::string_view name, int variablesReference,
                                   std::pmr::memory_resource *allocator) noexcept
{

  ASSERT(name == value.mName, "variable name {} != provided name {}", value.mName, name);
  const auto &t = *value.GetType();
  std::pmr::string result{allocator};
  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }})", name,
    t, t, variablesReference, value.Address());
}

std::optional<std::pmr::string>
InvalidValueVisualizer::Serialize(const Value &value, std::string_view, int,
                                  std::pmr::memory_resource *allocator) noexcept
{
  std::pmr::string result{allocator};
  FormatAndReturn(result,
                  R"({{ "name": "{}", "value": "could not resolve {}", "type": "{}", "variablesReference": 0 }})",
                  value.mName, value.mName, *value.GetType());
}

std::optional<std::pmr::string>
ArrayVisualizer::Serialize(const Value &value, std::string_view, int variablesReference,
                           std::pmr::memory_resource *allocator) noexcept
{
  auto &t = *value.GetType();
  const auto no_alias = t.ResolveAlias();
  std::pmr::string result{allocator};
  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}", "indexedVariables": {} }})",
    value.mName, t, t, variablesReference, value.Address(), no_alias->ArraySize());
}

std::optional<std::pmr::string>
CStringVisualizer::FormatValue(const Value &ptr, std::optional<u32> null_terminator,
                               std::pmr::memory_resource *allocator) noexcept
{
  const auto byte_span = ptr.FullMemoryView();
  if (byte_span.empty()) {
    return std::nullopt;
  }
  std::string_view cast{(const char *)byte_span.data(), null_terminator.value_or(byte_span.size_bytes())};
  std::pmr::string result{allocator};
  FormatAndReturn(result, "{}", cast);
}

std::optional<std::pmr::string>
CStringVisualizer::Serialize(const Value &value, std::string_view name, int,
                             std::pmr::memory_resource *allocator) noexcept
{
  const auto byte_span = value.FullMemoryView();
  if (byte_span.empty()) {
    return std::nullopt;
  }
  std::optional<u32> null_terminator = {};
  for (const auto [index, ch] : mdb::EnumerateView(byte_span)) {
    if (ch == 0) {
      null_terminator = index;
      break;
    }
  }

  std::string_view cast{(const char *)byte_span.data(), null_terminator.value_or(byte_span.size_bytes())};
  std::pmr::string result{allocator};
  FormatAndReturn(
    result,
    R"({{ "name": "{}", "value": "{}", "type": "const char *", "variablesReference": {}, "memoryReference": "{}" }})",
    name, cast, 0, value.Address());
}

#undef FormatAndReturn
} // namespace mdb::sym