/** LICENSE TEMPLATE */
#include "variablejs.h"
#include "js/ArrayBuffer.h"
#include "js/ArrayBufferMaybeShared.h"
#include "js/BigInt.h"
#include "js/CompilationAndEvaluation.h"
#include "js/Conversions.h"
#include "js/EnvironmentChain.h"
#include "js/ErrorReport.h"
#include "js/GCVector.h"
#include "js/Modules.h"
#include "js/PropertyAndElement.h"
#include "js/PropertyDescriptor.h"
#include "js/RootingAPI.h"
#include "js/Value.h"
#include "jsapi.h"
#include "mdbjs/util.h"
#include "symbolication/value_visualizer.h"
#include "utils/logger.h"
#include <js/ArrayBuffer.h> // For JS_NewArrayBuffer and JS_GetArrayBufferData
#include <js/experimental/TypedData.h>

#include <symbolication/objfile.h>
#include <symbolication/type.h>

namespace mdb::js {

/*static*/ bool
Variable::js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());
  args.rval().setBigInt(JS::NumberToBigInt(cx, var->ReferenceId()));
  return true;
}

/*static*/ bool
Variable::js_name(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());
  auto str = PrepareString(cx, var->mName);
  if (!str) {
    JS_ReportOutOfMemory(cx);
    return false;
  }
  args.rval().setString(str);
  return true;
}

// Function to extract "depth" and "nl" properties from a JSObject*
static bool
GetSerializeOptions(JSContext *cx, JS::HandleObject obj, sym::SerializeOptions &options)
{
  JS::RootedValue val(cx);

  // Check for "depth" property
  if (JS_GetProperty(cx, obj, "depth", &val) && val.isInt32()) {
    options.mDepth = val.toInt32();
  }

  // Check for "nl" property
  if (JS_GetProperty(cx, obj, "nl", &val) && val.isBoolean()) {
    options.mNewLineAfterMember = val.toBoolean();
  }

  return true;
}

/*static*/ bool
Variable::js_to_string(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  sym::SerializeOptions options{};
  if (args.length() == 1) {
    if (!args[0].isObject()) {
      JS_ReportErrorASCII(cx, "options to toString must be an object { depth: int, nl: boolean } that describes "
                              "levels to print and if newlines should be printed after fields");
      return false;
    }
    JS::Rooted<JSObject *> obj{cx, &args[0].toObject()};
    // options are default, if no opts are passed in.
    GetSerializeOptions(cx, obj, options);
  }

  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());

  std::string string;
  sym::JavascriptValueSerializer::Serialize(var, string, options);
  auto str = PrepareString(cx, string);
  if (!str) {
    JS_ReportOutOfMemory(cx);
    return false;
  }
  args.rval().setString(str);
  return true;
}

/* static */
bool
Variable::js_type_name(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());
  auto str = PrepareString(cx, var->GetType()->mName);
  if (!str) {
    JS_ReportOutOfMemory(cx);
    return false;
  }
  args.rval().setString(str);
  return true;
}

/* static */ bool
Variable::js_address(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());

  JS::BigInt *bigInt = JS::NumberToBigInt(cx, var->Address().get());
  if (!bigInt) {
    JS_ReportErrorASCII(cx, "Failed to create BigInt");
    return false;
  }

  // Return the BigInt to JavaScript
  args.rval().setBigInt(bigInt);
  return true;
}

/* static */ bool
Variable::js_bytes(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());
  const auto bytesSize = var->MemoryView().size_bytes();

  mozilla::UniquePtr<uint8_t[], JS::FreePolicy> buffer(static_cast<uint8_t *>(JS_malloc(cx, bytesSize)));
  std::copy_n(var->MemoryView().data(), bytesSize, buffer.get());
  JS::Rooted<JSObject *> arrayBuffer(cx, JS::NewArrayBufferWithContents(cx, bytesSize, std::move(buffer)));
  auto arrayObject = JS_NewUint8ArrayWithBuffer(cx, arrayBuffer, 0, static_cast<int64_t>(bytesSize));
  args.rval().setObject(*arrayObject);

  return true;
}

/* static */
bool
Variable::js_is_live(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());

  args.rval().setBoolean(var->IsLive());
  return true;
}

/* static */
bool
Variable::js_set_value(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  if (args.length() != 1) {
    JS_ReportErrorASCII(cx, "Function expects a value that the variable can be overwritten with.");
    return false;
  }

  auto var = Get(callee.get());
  if (args[0].isInt32()) {
    int value = args[0].toInt32();
    if (!var->WritePrimitive(value)) {
      JS_ReportErrorASCII(cx, "Failed to set value");
      return false;
    }
  } else if (args[0].isDouble()) {
    double value;
    if (!JS::ToNumber(cx, args[0], &value)) {
      JS_ReportErrorASCII(cx, "Conversion to number failed");
      return false;
    }
    if (!var->WritePrimitive(value)) {
      JS_ReportErrorASCII(cx, "Failed to set value");
      return false;
    }
  } else if (args[0].isBigInt()) {
    auto bigInt = args[0].toBigInt();
    if (JS::BigIntIsNegative(bigInt)) {
      int64_t value = JS::ToBigInt64(bigInt);
      if (!var->WritePrimitive(value)) {
        JS_ReportErrorASCII(cx, "Failed to set value");
        return false;
      }
    } else {
      uint64_t value = JS::ToBigUint64(bigInt);
      if (!var->WritePrimitive(value)) {
        JS_ReportErrorASCII(cx, "Failed to set value");
        return false;
      }
    }
  } else {
    JS_ReportErrorASCII(cx, "Over-write value type unsupported at the moment");
    return false;
  }

  return true;
}

/* static */
bool
Variable::js_dereference(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());
  if (!var->GetType()->IsReference()) {
    JS_ReportErrorASCII(cx, "value is not a reference");
    return false;
  }

  JS_ReportErrorASCII(cx, "dereference not implemented yet");
  return false;
}

bool
Variable::resolve(JSContext *cx, JS::HandleId id, bool *resolved) noexcept
{
  JS::Rooted<JS::Value> idValue{cx};
  if (!JS_IdToValue(cx, id, &idValue)) {
    return false;
  }

  if (!idValue.isString()) {
    return false;
  }

  JS::Rooted<JSString *> str{cx, idValue.toString()};
  std::string propertyName;
  if (!ToStdString(cx, str, propertyName)) {
    return false;
  }
  auto value = Get();
  if (!value->HasMember(propertyName)) {
    return true;
  }
  auto member = value->GetMember(propertyName);
  if (member) {
    JS::Rooted<JSObject *> memberObject{cx, Create(cx, member)};
    if (!memberObject) {
      return false;
    }
    JS::Rooted<JSObject *> thisObject{cx, AsObject(this)};
    JS_DefinePropertyById(cx, thisObject, id, memberObject, JSPROP_ENUMERATE);
    *resolved = true;
  }
  return true;
}

} // namespace mdb::js