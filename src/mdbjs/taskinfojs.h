/** LICENSE TEMPLATE */
#pragma once
#include "bp.h"
#include "js/CallArgs.h"
#include "js/PropertySpec.h"
#include "js/RootingAPI.h"
#include "mdbjs/jsobject.h"
#include "task.h"
#include "typedefs.h"
#include "utils/smartptr.h"
#include <cstring>

namespace mdb::js {

struct TaskInfo : public RefPtrJsObject<mdb::js::TaskInfo, mdb::TaskInfo, StringLiteral{"Task"}>
{
  enum Slots
  {
    ThisPointer,
    SlotCount
  };

  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static void
  DefineProperties(JSContext *cx, JSObject *thisObj) noexcept
  {
    constexpr JSPropertySpec ReadOnlyPropertySpecs[]{JS_PS_END};
  }

  static void
  DefineFunctions(JSContext *cx, JSObject *thisObj) noexcept
  {
    static constexpr JSFunctionSpec breakpointFunctions[] = {JS_FN("id", &js_id, 0, 0), JS_FS_END};
  }
};

} // namespace mdb::js