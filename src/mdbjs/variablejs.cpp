/** LICENSE TEMPLATE */
#include "variablejs.h"
#include "mdbjs/mdbjs.h"

// mdb
#include <lib/arena_allocator.h>
#include <mdbjs/jsobject.h>
#include <mdbjs/util.h>
#include <symbolication/dwarf_defs.h>
#include <symbolication/objfile.h>
#include <symbolication/type.h>
#include <symbolication/value_visualizer.h>
#include <utils/scope_defer.h>

// dependency
#include <mdbjs/include-quickjs.h>

namespace mdb::js {

static constexpr auto kBindingDataError = "Could not read sym::Value*";

static constexpr auto IsCurrentValue = [](const sym::Value &v) { return v.IsValidValue() && v.IsLive(); };

/* static */ JSValue
JsVariable::Id(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewUint32(context, pointer->ReferenceId());
}

/* static */ JSValue
JsVariable::Name(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewStringLen(context, pointer->mName.StringView().data(), pointer->mName.StringView().size());
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
    if (opts.mDepth < 2) {
      opts.mDepth = 2;
    }
  }

  if (!JS_IsUndefined(newLine)) {
    opts.mNewLineAfterMember = JS_ToBool(context, newLine);
  }

  return opts;
}

/* static */ JSValue
JsVariable::ToString(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  auto serializeOptions = GetSerializeOptionsFromJsArg(context, argCount, argv).value_or({});

  auto scopedTemporary = Scripting::GetAllocator()->ScopeAllocation();
  std::pmr::string buffer{ scopedTemporary.GetAllocator() };
  buffer.reserve(4096);
  sym::JavascriptValueSerializer::Serialize(pointer, buffer, serializeOptions);

  return JS_NewStringLen(context, buffer.data(), buffer.size());
}

/* static */ JSValue
JsVariable::TypeName(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewStringLen(context, pointer->GetType()->mName->data(), pointer->GetType()->mName->size());
}

/* static */ JSValue
JsVariable::Address(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewInt64(context, pointer->Address().GetRaw());
}

/* static */ JSValue
JsVariable::Dereference(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_ThrowTypeError(context, "Variable::Dereference not yet implemented.");
}

/* static */ JSValue
JsVariable::Bytes(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);

  const auto sizeBytes = pointer->MemoryView().size_bytes();
  auto bytes = new u8[sizeBytes];
  std::memcpy(bytes, pointer->MemoryView().data(), sizeBytes);
  return JS_NewArrayBuffer(
    context, bytes, sizeBytes, [](JSRuntime *, void *, void *ptr) { delete (u8 *)ptr; }, nullptr, false);
}

/* static */ JSValue
JsVariable::IsLive(JSContext *context, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  return JS_NewBool(context, pointer->IsLive());
}

/* static */
JSValue
JsVariable::SetValue(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);
  if (!IsCurrentValue(*pointer)) {
    return JS_ThrowTypeError(context, "Can't set the value of a variable that no longer is alive.");
  }

  if (argCount != 1) {
    return JS_ThrowTypeError(
      context, "method takes 1 argument, the contents that shall be written to the variable's backing storage.");
  }

  const auto arg = argv[0];
  const auto argTag = JS_VALUE_GET_TAG(arg);

  switch (argTag) {
  case JS_TAG_INT: {
    int32_t value = 0;
    JS_ToInt32(context, &value, arg);
    if (!pointer->WritePrimitive(value)) {
      return JS_ThrowTypeError(context, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_BIG_INT: {
    int64_t value = 0;
    JS_ToBigInt64(context, &value, arg);
    if (!pointer->WritePrimitive(value)) {
      return JS_ThrowTypeError(context, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_FLOAT64: {
    double value = 0;
    JS_ToFloat64(context, &value, arg);
    if (!pointer->WritePrimitive(value)) {
      return JS_ThrowTypeError(context, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_BOOL: {
    bool value = JS_ToBool(context, arg);
    if (!pointer->WritePrimitive(value)) {
      return JS_ThrowTypeError(context, "Failed to set value of variable");
    }
  } break;
  case JS_TAG_STRING: // TODO: Implement
    [[fallthrough]];
  case JS_TAG_STRING_ROPE: // TODO: Implement
    [[fallthrough]];
  default:
    break;
  }
  return JS_ThrowTypeError(
    context, "Unsupported JS Value tag for this operation (Variable::SetValue): %d", argTag);
}

/* static */
JSValue
JsVariable::ToPrimitive(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  PROFILE_SCOPE("JsVariable::ToPrimitive", logging::kInterpreter);
  auto *value = GetThisOrReturnException(value, "Could not read sym::Value");
  QuickJsString hintArg;

  if (argCount > 0 && JS_IsString(argv[0])) {
    hintArg = QuickJsString::FromValue(context, argv[0]);
  }

  sym::Type *type = value->GetType();

  if (const auto baseType = type->GetBaseTypeIfPrimitive(); baseType.has_value()) {
    auto byteSpan = value->MemoryView();
    switch (*baseType) {
    case BaseTypeEncoding::DW_ATE_address: {
      std::uintptr_t value = sym::BitCopy<std::uintptr_t>(byteSpan);
      return JS_NewBigUint64(context, value);
    }
    case BaseTypeEncoding::DW_ATE_boolean: {
      bool value = sym::BitCopy<bool>(byteSpan);
      return JS_NewBool(context, value);
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
      return JS_NewFloat64(context, doubleValue);
    }
    case BaseTypeEncoding::DW_ATE_signed:
      [[fallthrough]];
    case BaseTypeEncoding::DW_ATE_signed_char: {
      switch (type->Size()) {
      case 1: {
        int res = int{ sym::BitCopy<signed char>(byteSpan) };
        return JS_NewInt32(context, res);
      }
      case 2: {
        int res = int{ sym::BitCopy<signed short>(byteSpan) };
        return JS_NewInt32(context, res);
      }
      case 4: {
        int res = sym::BitCopy<int>(byteSpan);
        return JS_NewInt32(context, res);
      }
      case 8: {
        i64 res = sym::BitCopy<i64>(byteSpan);
        return JS_NewInt64(context, res);
      }
      }
    }
    case BaseTypeEncoding::DW_ATE_unsigned:
      [[fallthrough]];
    case BaseTypeEncoding::DW_ATE_unsigned_char: {
      switch (type->Size()) {
      case 1: {
        u8 res = sym::BitCopy<unsigned char>(byteSpan);
        return JS_NewUint32(context, res);
      }
      case 2: {
        u16 res = sym::BitCopy<unsigned short>(byteSpan);
        return JS_NewUint32(context, res);
      }
      case 4: {
        u32 res = sym::BitCopy<u32>(byteSpan);
        return JS_NewUint32(context, res);
      }
      case 8: {
        u64 res = sym::BitCopy<u64>(byteSpan);
        return JS_NewBigUint64(context, res);
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
      return JS_NewString(context, "[object JsVariable]");
      break;
    default:
      PANIC("Added type that is unhandled!");
    }
  } else if (type->IsReference()) {
    DBGLOG(core, "We've not implemented string comparisons.");
  }
  return JS_UNDEFINED;
}

/* static */ JSValue
JsVariable::GetMemberVariable(
  JSContext *context, JSValueConst thisValue, JSAtom prop, [[maybe_unused]] JSValueConst receiverValue) noexcept
{
  JSPropertyDescriptor desc;
  if (JS_GetOwnProperty(context, &desc, thisValue, prop)) {
    JSValue val = JS_DupValue(context, desc.value);
    return val;
  }
  auto pointer = GetThisOrReturnException(pointer, kBindingDataError);

  // TODO: Implement our own DebuggerAtom type, which we can share with QuickJs, this will make future
  // lookups/comparisons between strings faster. This todo has duplicates.

  const char *propertyName = JS_AtomToCString(context, prop);
  ScopedDefer defer{ [&]() {
    if (propertyName) {
      JS_FreeCString(context, propertyName);
    }
  } };

  auto member = pointer->GetMember(propertyName);

  if (!member) {
    return JS_ThrowTypeError(context,
      "[mdbjs]: Type <%s> doesn't have a member called '%s'",
      pointer->GetType()->mName->data(),
      propertyName);
  }

  return JsVariable::CreateValue(context, member);
}

} // namespace mdb::js

#undef GetThisOrReturnException