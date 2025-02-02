#include "variablejs.h"
#include "js/ArrayBuffer.h"
#include "js/ArrayBufferMaybeShared.h"
#include "js/BigInt.h"
#include "js/CompilationAndEvaluation.h"
#include "js/EnvironmentChain.h"
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

#include <symbolication/type.h>

namespace mdb::js {

/*static*/ bool
Variable::js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto v = JS::GetReservedSlot(callee, Slots::VariablesReference);
  args.rval().set(v);
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

/*static*/ bool
Variable::js_to_string(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  TODO(__PRETTY_FUNCTION__);
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto var = Get(callee.get());
  var->GetVisualizer()->Serialize(*var, var->mName, var->ReferenceId(), nullptr);
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
/* static */ bool
Variable::js_dereference(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  TODO(__PRETTY_FUNCTION__);
}

/* static */
void
Variable::Finalize(JSContext *cx, JS::Handle<JSObject *> object, sym::Value *value, int variablesReference)
{
  JS_SetReservedSlot(object, Slots::VariablesReference, JS::Int32Value(variablesReference));
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