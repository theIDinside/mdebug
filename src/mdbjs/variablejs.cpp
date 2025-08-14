/** LICENSE TEMPLATE */
#include "variablejs.h"
#include "utils/scope_defer.h"

// mdb
#include <lib/arena_allocator.h>
#include <mdbjs/jsobject.h>
#include <symbolication/objfile.h>
#include <symbolication/type.h>
#include <symbolication/value_visualizer.h>

// dependencies
#include <quickjs/quickjs.h>

namespace mdb::js {

static constexpr auto JsVariableOpaqueDataErrorMessage = "Could not read sym::Value*";

static constexpr auto IsCurrentValue = [](const sym::Value &v) { return v.IsValidValue() && v.IsLive(); };

#define GetNativeSelf() GetThisOrReturnException(self, JsVariableOpaqueDataErrorMessage)

/* static */ JSValue
JsVariable::Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
  return JS_NewUint32(context, pointer->ReferenceId());
}

/* static */ JSValue
JsVariable::Name(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
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
JsVariable::ToString(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
  auto serializeOptions = GetSerializeOptionsFromJsArg(context, argCount, argv).value_or({});

  mdb::alloc::StackBufferResource<4096> alloc{};
  std::pmr::string buffer{ &alloc };
  buffer.reserve(alloc.GetCapacity());
  sym::JavascriptValueSerializer::Serialize(pointer, buffer, serializeOptions);

  return JS_NewStringLen(context, buffer.data(), buffer.size());
}

/* static */ JSValue
JsVariable::TypeName(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
  return JS_NewStringLen(context, pointer->GetType()->mName->data(), pointer->GetType()->mName->size());
}

/* static */ JSValue
JsVariable::Address(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
  return JS_NewInt64(context, pointer->Address().GetRaw());
}

/* static */ JSValue
JsVariable::Dereference(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
  return JS_ThrowTypeError(context, "Variable::Dereference not yet implemented.");
}

/* static */ JSValue
JsVariable::Bytes(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");

  const auto sizeBytes = pointer->MemoryView().size_bytes();
  auto bytes = new u8[sizeBytes];
  std::memcpy(bytes, pointer->MemoryView().data(), sizeBytes);
  return JS_NewArrayBuffer(
    context, bytes, sizeBytes, [](JSRuntime *rt, void *opaque, void *ptr) { delete (u8 *)ptr; }, nullptr, false);
}

/* static */ JSValue
JsVariable::IsLive(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
  return JS_NewBool(context, pointer->IsLive());
}

/* static */
JSValue
JsVariable::SetValue(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");
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

/* static */ void
JsVariable::CacheLayout(JSContext *context, sym::Value *value) noexcept
{
  // TODO
}

/* static */ JSValue
JsVariable::GetMemberVariable(
  JSContext *context, JSValueConst thisValue, JSAtom prop, JSValueConst receiverValue) noexcept
{
  auto pointer = GetThisOrReturnException(pointer, "Could not read sym::Value*");

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
    return JS_ThrowTypeError(
      context, "Type %s doesn't have a member called %s", pointer->GetType()->mName->data(), propertyName);
  }

  return JsVariable::CreateValue(context, member);
}

} // namespace mdb::js

#undef GetThis