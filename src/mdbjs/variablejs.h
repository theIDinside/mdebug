/** LICENSE TEMPLATE */
#pragma once

#include "js/TypeDecls.h"
#include "mdbjs/jsobject.h"
#include "symbolication/value.h"
#include "typedefs.h"
#include "utils/smartptr.h"
#include <cstring>

namespace mdb {
class VariableObject
{
  INTERNAL_REFERENCE_COUNT(VariableObject);
};
}; // namespace mdb

namespace mdb::js {
struct Variable : public RefPtrJsObject<mdb::js::Variable, sym::Value, StringLiteral{"Variable"}>
{
  enum Slots
  {
    ThisPointer,
    VariablesReference,
    SlotCount
  };

  static void Configure(JSContext *cx, JS::Handle<JSObject *> object, sym::Value *value) noexcept;
  static void Finalize(JSContext *cx, JS::Handle<JSObject *> object, sym::Value *value, int variablesReference);

  bool resolve(JSContext *cx, JS::HandleId id, bool *resolved) noexcept;

  /** Return the variables reference (id) for this variable*/
  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  /** Return the name of this variable (if it has any). */
  static bool js_name(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  /** Return the printable for this variable. */
  static bool js_to_string(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  /** Return the address that this value was read from. */
  static bool js_address(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  /** Return the bytes that constitute this value. Returned as an Uint8Array. */
  static bool js_bytes(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  /** Dereference this value if it's a reference type. Throws an exception if it can't. */
  static bool js_dereference(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static constexpr JSFunctionSpec FunctionSpec[] = {JS_FN("id", &js_id, 0, 0),
                                                    JS_FN("name", &js_name, 0, 0),
                                                    JS_FN("to_string", &js_to_string, 0, 0),
                                                    JS_FN("address", &js_address, 0, 0),
                                                    JS_FN("bytes", &js_bytes, 0, 0),
                                                    JS_FN("dereference", &js_dereference, 0, 0),
                                                    JS_FS_END};
  // Uncomment when you want to define properties
  // static constexpr JSPropertySpec PropertiesSpec[]{JS_PS_END};
};
} // namespace mdb::js