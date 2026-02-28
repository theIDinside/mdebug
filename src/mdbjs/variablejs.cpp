/** LICENSE TEMPLATE */
#include "variablejs.h"
#include "quickjs.h"

// mdb
#include <lib/arena_allocator.h>
#include <mdbjs/jsobject.h>
#include <mdbjs/mdbjs.h>
#include <mdbjs/util.h>
#include <symbolication/dwarf_defs.h>
#include <symbolication/objfile.h>
#include <symbolication/type.h>
#include <symbolication/value_visualizer.h>
#include <task.h>
#include <utils/logger.h>
#include <utils/scope_defer.h>

// dependency
#include <mdbjs/include-quickjs.h>

#include <algorithm>

namespace mdb::js {

static constexpr auto kBindingDataError = "Could not read sym::Value*";
static constexpr auto kTypeBindingDataError = "Could not read sym::Type*";

static constexpr auto IsCurrentValue = [](const sym::Value &v) { return v.IsValidValue() && v.IsLive(); };

/* static */ JSValue
JsType::Name(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);
  return JS_NewStringLen(cx, type->mName->data(), type->mName->size());
}

/* static */ JSValue
JsType::ToString(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);

  auto scopedTemporary = Scripting::GetAllocator()->ScopeAllocation();
  std::pmr::string buffer{ scopedTemporary.GetAllocator() };
  buffer.reserve(256);

  // Format the type using the std::formatter<sym::Type>
  std::format_to(std::back_inserter(buffer), "{}", *type);

  return JS_NewStringLen(cx, buffer.data(), buffer.size());
}

/* static */ JSValue
JsType::SizeOf(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);
  return JS_NewUint32(cx, type->Size());
}

/* static */ JSValue
JsType::PointeeSize(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);
  return JS_NewUint32(cx, type->TypeDescribingLayoutOfThis()->Size());
}

/* static */ JSValue
JsType::TemplateArgument(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);

  if (argCount != 1 || !JS_IsNumber(argv[0])) {
    return JS_ThrowTypeError(cx, "TemplateArgument requires a number argument (index)");
  }

  u32 index = 0;
  JS_ToUint32(cx, &index, argv[0]);

  const auto *templateArg = type->TemplateTypeParameter(index);

  if (!templateArg) {
    return JS_ThrowRangeError(cx, "Template argument index %u out of range", index);
  }

  if (templateArg->IsTemplateValueParameter()) {
    auto byteBuffer = ByteBuffer::Create(templateArg->mConstValueBytes.size());
    (void)byteBuffer->Write(templateArg->mConstValueBytes);

    auto memoryContents = std::make_shared<sym::SynthesizedMemoryContentsObject>(
      AddrPtr{ nullptr }, AddrPtr{ templateArg->mConstValueBytes.size() }, std::move(byteBuffer));

    auto value = Ref<sym::Value>::MakeShared(nullptr, *templateArg->mType, 0U, memoryContents, nullptr);

    return JsVariable::CreateValue(cx, std::move(value));
  }
  // This is a template type parameter
  return JsType::CreateValue(cx, templateArg->mType);
}

/* static */ JSValue
JsType::Member(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);

  if (argCount != 1 || !JS_IsString(argv[0])) {
    return JS_ThrowTypeError(cx, "Member method requires a string argument (member name)");
  }

  const char *memberName = JS_ToCString(cx, argv[0]);
  ScopedDefer defer{ [&]() {
    if (memberName) {
      JS_FreeCString(cx, memberName);
    }
  } };

  // Get the member fields and search for the requested member
  const auto &fields = type->MemberFields();
  for (const auto &field : fields) {
    if (field.mName == memberName) {
      return JsType::CreateValue(cx, field.mType.Ptr());
    }
  }

  // Don't do this allocation every time.

  const auto msg = std::format("Type '{}' does not have a member named '{}'", type->mName->data(), memberName);

  return JS_ThrowTypeError(cx, "%s", msg.c_str());
}

/* static */ JSValue
JsType::Members(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);

  const auto &fields = type->MemberFields();
  JSValue array = JS_NewArray(cx);

  for (u32 i = 0; i < fields.size(); ++i) {
    JSValue memberType = JsType::CreateValue(cx, fields[i].mType.Ptr());
    JS_SetPropertyUint32(cx, array, i, memberType);
  }

  return array;
}

/* static */ auto
JsType::ToPrimitive(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept -> JSValue
{
  sym::Type *type = GetThisOrReturnException(type, kTypeBindingDataError);

  // For types, we return the name as a string representation
  return JS_NewStringLen(cx, type->mName->data(), type->mName->size());
}

/* static */ JSValue
JsVariable::Id(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Value *type = GetThisOrReturnException(type, kBindingDataError);
  return JS_NewUint32(cx, type->ReferenceId());
}

/* static */ JSValue
JsVariable::Name(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Value *type = GetThisOrReturnException(type, kBindingDataError);
  return JS_NewStringLen(cx, type->mName.StringView().data(), type->mName.StringView().size());
}

static inline std::optional<sym::SerializeOptions>
GetSerializeOptionsFromJsArg(JSContext *context, int argCount, JSValue *argv) noexcept
{
  if (argCount < 1) {
    return {};
  }

  const auto val = argv[0];

  if (JS_IsUndefined(val) || !JS_IsObject(val)) {
    return {};
  }

  auto depth = JS_GetPropertyStr(context, val, sym::SerializeOptions::JsDepthPropertyString);
  auto newLine = JS_GetPropertyStr(context, val, sym::SerializeOptions::JsNewlinePropertyString);

  sym::SerializeOptions opts;

  if (!JS_IsUndefined(depth)) {
    JS_ToInt32(context, &opts.mDepth, depth);
    // Don't let the user do something stupid.
    opts.mDepth = std::max(opts.mDepth, 2);
  }

  if (!JS_IsUndefined(newLine)) {
    opts.mNewLineAfterMember = JS_ToBool(context, newLine);
  }

  return opts;
}

/* static */ JSValue
JsVariable::ToString(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Value *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  auto serializeOptions = GetSerializeOptionsFromJsArg(cx, argCount, argv).value_or({});

  auto scopedTemporary = Scripting::GetAllocator()->ScopeAllocation();
  std::pmr::string buffer{ scopedTemporary.GetAllocator() };
  buffer.reserve(4096);
  sym::JavascriptValueSerializer::Serialize(pointer, buffer, serializeOptions);

  return JS_NewStringLen(cx, buffer.data(), buffer.size());
}

/* static */ JSValue
JsVariable::TypeName(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewStringLen(cx, pointer->GetType()->mName->data(), pointer->GetType()->mName->size());
}

/* static */ JSValue
JsVariable::Address(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewBigUint64(cx, pointer->Address().GetRaw());
}

/* static */ JSValue
JsVariable::Dereference(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Value *value = GetThisOrReturnException(value, kBindingDataError);
  u32 derefCount = 1;

  if (argCount > 0) {
    if (!JS_IsNumber(argv[0])) {
      return JS_ThrowTypeError(cx, "deref argument must be a number");
    }
    JS_ToUint32(cx, &derefCount, argv[0]);
  }

  const auto v = value->Dereference(derefCount).and_then([&](auto &&v) {
    return std::expected<JSValue, sym::ValueError>{ JsVariable::CreateValue(cx, std::move(v[0])) };
  });

  if (!v.has_value()) {
    switch (v.error().mType) {
    case sym::ValueErrorType::InvalidSize:
      return JS_ThrowTypeError(cx, "Dereference Error: Value is not size 8");
    case sym::ValueErrorType::NotAReference:
      return JS_ThrowTypeError(cx, "Dereference Error: Value is not a reference");
    case sym::ValueErrorType::InvalidMemoryAddress:
      return JS_ThrowTypeError(
        cx, "Dereference Error: Invalid memory address 0x%lx.", v.error().mAddress.GetRaw());
    case sym::ValueErrorType::NoVariableContext:
      return JS_ThrowTypeError(cx, "Dereference Error: No variable context.");
    }
  }

  return *v;
}

/* static */ JSValue
JsVariable::Bytes(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto *pointer = GetThisOrReturnException(pointer, kBindingDataError);

  const auto sizeBytes = pointer->MemoryView().size_bytes();
  u8 *bytes = new u8[sizeBytes];
  std::memcpy(bytes, pointer->MemoryView().data(), sizeBytes);
  return JS_NewArrayBuffer(
    cx, bytes, sizeBytes, [](JSRuntime *, void *, void *ptr) { delete (u8 *)ptr; }, nullptr, false);
}

/* static */ JSValue
JsVariable::IsLive(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewBool(cx, pointer->IsLive());
}

/* static */
JSValue
JsVariable::SetValue(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  sym::Value *type = GetThisOrReturnException(type, kBindingDataError);
  if (!IsCurrentValue(*type)) {
    return JS_ThrowTypeError(cx, "Can't set the value of a variable that no longer is alive.");
  }

  if (argCount != 1) {
    return JS_ThrowTypeError(
      cx, "method takes 1 argument, the contents that shall be written to the variable's backing storage.");
  }

  const auto arg = argv[0];
  const auto argTag = JS_VALUE_GET_TAG(arg);

  switch (argTag) {
  case JS_TAG_INT: {
    int32_t value = 0;
    JS_ToInt32(cx, &value, arg);
    if (!type->WritePrimitive(value)) {
      return JS_ThrowTypeError(cx, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_BIG_INT: {
    int64_t value = 0;
    JS_ToBigInt64(cx, &value, arg);
    if (!type->WritePrimitive(value)) {
      return JS_ThrowTypeError(cx, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_FLOAT64: {
    double value = 0;
    JS_ToFloat64(cx, &value, arg);
    if (!type->WritePrimitive(value)) {
      return JS_ThrowTypeError(cx, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_BOOL: {
    bool value = JS_ToBool(cx, arg);
    if (!type->WritePrimitive(value)) {
      return JS_ThrowTypeError(cx, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_STRING: // TODO: Implement
    [[fallthrough]];
  case JS_TAG_STRING_ROPE: // TODO: Implement
    [[fallthrough]];
  default:
    break;
  }
  return JS_ThrowTypeError(cx, "Unsupported JS Value tag for this operation (Variable::SetValue): %d", argTag);
}

template <typename To>
To
BitCopyAndMaybeProcessBitField(std::span<const u8> from, const sym::Value &value)
{
  static_assert(std::is_trivial_v<To>, "Target of bit copy must be trivially constructible.");

  // Non-bitfield values is returned as-is.
  const auto bitField = value.BitField();
  return bitField
    .transform([&](const sym::BitField &field) {
      u64 rawBits = 0;
      std::memcpy(&rawBits, from.data(), std::min(sizeof(u64), from.size()));
      return static_cast<To>(field.ExtractBits(rawBits));
    })
    .or_else([&]() -> std::optional<To> {
      To result{};
      std::memcpy(&result, from.data(), std::min(sizeof(To), from.size()));
      return result;
    })
    .value();
}

/* static */
JSValue
JsVariable::ToPrimitive(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  PROFILE_SCOPE("JsVariable::ToPrimitive", logging::kInterpreter);
  auto *value = GetThisOrReturnException(value, "Could not read sym::Value");
  QuickJsString hintArg;

  if (argCount > 0 && JS_IsString(argv[0])) {
    hintArg = QuickJsString::FromValue(cx, argv[0]);
  }

  sym::Type *type = value->GetType();

  if (const auto baseType = type->GetBaseTypeIfPrimitive(); baseType.has_value()) {
    auto byteSpan = value->MemoryView();
    switch (*baseType) {
    case BaseTypeEncoding::DW_ATE_address: {
      auto v = BitCopyAndMaybeProcessBitField<std::uintptr_t>(byteSpan, *value);
      return JS_NewBigUint64(cx, v);
    }
    case BaseTypeEncoding::DW_ATE_boolean: {
      bool v = BitCopyAndMaybeProcessBitField<bool>(byteSpan, *value);
      return JS_NewBool(cx, v);
    }
    case BaseTypeEncoding::DW_ATE_float: {
      double doubleValue;
      switch (type->Size()) {
      case 4:
        doubleValue = double{ sym::BitCopy<float>(byteSpan) };
        break;
      case 8:
        doubleValue = sym::BitCopy<double>(byteSpan);
        break;
      default:
        PANIC("Unexpected floating point size");
      }
      return JS_NewFloat64(cx, doubleValue);
    }
    case BaseTypeEncoding::DW_ATE_signed:
      [[fallthrough]];
    case BaseTypeEncoding::DW_ATE_signed_char: {
      switch (type->Size()) {
      case 1: {
        int res = int{ BitCopyAndMaybeProcessBitField<signed char>(byteSpan, *value) };
        return JS_NewInt32(cx, res);
      }
      case 2: {
        int res = int{ BitCopyAndMaybeProcessBitField<signed short>(byteSpan, *value) };
        return JS_NewInt32(cx, res);
      }
      case 4: {
        int res = BitCopyAndMaybeProcessBitField<int>(byteSpan, *value);
        return JS_NewInt32(cx, res);
      }
      case 8: {
        i64 res = BitCopyAndMaybeProcessBitField<i64>(byteSpan, *value);
        return JS_NewInt64(cx, res);
      }
      }
    }
    case BaseTypeEncoding::DW_ATE_unsigned:
      [[fallthrough]];
    case BaseTypeEncoding::DW_ATE_unsigned_char: {
      switch (type->Size()) {
      case 1: {
        u8 res = BitCopyAndMaybeProcessBitField<unsigned char>(byteSpan, *value);
        return JS_NewUint32(cx, res);
      }
      case 2: {
        u16 res = BitCopyAndMaybeProcessBitField<unsigned short>(byteSpan, *value);
        return JS_NewUint32(cx, res);
      }
      case 4: {
        u32 res = BitCopyAndMaybeProcessBitField<u32>(byteSpan, *value);
        return JS_NewUint32(cx, res);
      }
      case 8: {
        u64 res = BitCopyAndMaybeProcessBitField<u64>(byteSpan, *value);
        return JS_NewBigUint64(cx, res);
      }
      }
    }
    case BaseTypeEncoding::DW_ATE_complex_float:
    case BaseTypeEncoding::DW_ATE_imaginary_float:
    case BaseTypeEncoding::DW_ATE_packed_decimal:
    case BaseTypeEncoding::DW_ATE_numeric_string:
    case BaseTypeEncoding::DW_ATE_edited:
    case BaseTypeEncoding::DW_ATE_signed_fixed:
    case BaseTypeEncoding::DW_ATE_unsigned_fixed:
    case BaseTypeEncoding::DW_ATE_decimal_float:
    case BaseTypeEncoding::DW_ATE_UTF:
    case BaseTypeEncoding::DW_ATE_UCS:
    case BaseTypeEncoding::DW_ATE_ASCII:
    case BaseTypeEncoding::DW_ATE_lo_user:
    case BaseTypeEncoding::DW_ATE_hi_user:
      return JS_NewString(cx, "[object JsVariable]");
      break;
    default:
      PANIC("Added type that is unhandled!");
    }
  } else if (type->IsReference()) {
    // For pointers and references, return the address as a BigInt for arithmetic operations
    auto address = value->ToRemotePointer();
    if (!address.has_value()) {
      return JS_ThrowTypeError(cx, "Failed to read pointer value");
    }
    return JS_NewBigUint64(cx, address->GetRaw());
  }

  // For non-primitive, non-pointer types, return a string representation
  return JS_NewString(cx, "[object JsVariable]");
}

/* static */ JSValue
JsVariable::Type(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto *value = GetThisOrReturnException(value, "Could not read sym::Value");
  return JsType::CreateValue(cx, value->GetType());
}

/* static */ JSValue
JsVariable::Member(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  if (argCount != 1 || !JS_IsString(argv[0])) {
    return JS_ThrowTypeError(cx, "Member method requires a string argument (member name)");
  }

  auto memberName = QuickJsString::FromValue(cx, argv[0]);

  sym::Value *value = GetThisOrReturnException(value, kTypeBindingDataError);
  sym::Type *type = value->EnsureTypeResolved();

  auto memberValue = value->GetMember(memberName.mString);

  if (!memberValue) {
    const auto msg = std::format("Type '{}' does not have a member named '{}'", *type, memberName.mString);

    return JS_ThrowTypeError(cx, "%s", msg.c_str());
  }
  return JsVariable::CreateValue(cx, std::move(memberValue));
}

/* static */ JSValue
JsVariable::Members(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Value *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  JSValue array = JS_NewArray(cx);

  auto i = 0U;
  (void)pointer->PushMemberValue([&i, cx, array](Ref<sym::Value> value) {
    JSValue memberType = JsVariable::CreateValue(cx, std::move(value));
    JS_SetPropertyUint32(cx, array, i, memberType);
    ++i;
    return true;
  });

  return array;
}

/* static */ JSValue
JsVariable::MemberCount(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  sym::Value *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  const size_t count = pointer->EnsureTypeResolved()->MemberFields().size();
  return JS_NewUint32(cx, count);
}

// Note, should (in time) turn a type T* to a T[]. If you have a type T* and you want an array of pointers,
// you need to first promote, to T **, then .asArray -> T*[]
/* static */ JSValue
JsVariable::AsArray(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  JSValue array = JS_NewArray(cx);

  if (argCount != 1 || !JS_IsNumber(argv[0])) {
    return JS_ThrowTypeError(cx, "asArray takes a number as an argument");
  }

  sym::Value *pointer = GetThisOrReturnException(pointer, kBindingDataError);
  auto res = pointer->ToRemotePointer();
  if (!res.has_value() && !pointer->IsSynthetic()) {
    return JS_ThrowTypeError(cx, "value is not a representation of a memory address");
  }

  u32 count = 0;
  JS_ToUint32(cx, &count, argv[0]);

  auto varContext = pointer->GetVariableContext();
  if (!varContext) {
    return JS_ThrowTypeError(cx, "No variable context found");
  }

  auto synthetic = sym::MemoryContentsObject::CreateSyntheticVariable(*varContext,
    res.value(),
    sym::SyntheticType{ .mLayoutType = pointer->GetType()->TypeDescribingLayoutOfThis(), .mCount = count },
    true);

  size_t i = 0;
  synthetic->PushMemberValue([&](Ref<sym::Value> value) {
    // we want everyone
    JS_SetPropertyUint32(cx, array, i, JsVariable::CreateValue(cx, std::move(value)));
    ++i;
    return true;
  });

  return array;
}

/* static */ JSValue
JsVariable::GetMemberVariable(
  JSContext *cx, JSValueConst thisValue, JSAtom prop, [[maybe_unused]] JSValueConst receiverValue) noexcept
{
  JSPropertyDescriptor desc;
  if (JS_GetOwnProperty(cx, &desc, thisValue, prop)) {
    JSValue val = JS_DupValue(cx, desc.value);
    return val;
  }
  sym::Value *pointer = GetThisOrReturnException(pointer, kBindingDataError);

  // TODO: Implement our own DebuggerAtom type, which we can share with QuickJs, this will make future
  // lookups/comparisons between strings faster. This todo has duplicates.

  const char *propertyName = JS_AtomToCString(cx, prop);
  ScopedDefer defer{ [&]() {
    if (propertyName) {
      JS_FreeCString(cx, propertyName);
    }
  } };

  auto member = pointer->GetMember(propertyName);

  if (!member) {
    // TODO: Stop allocation error msg strings
    const auto err = std::format(
      "[mdbjs]: Type <{}> doesn't have a member called '{}'", pointer->GetType()->mName->data(), propertyName);
    return JS_ThrowTypeError(cx, "%s", err.c_str());
  }

  return JsVariable::CreateValue(cx, member);
}

} // namespace mdb::js

#undef GetThisOrReturnException