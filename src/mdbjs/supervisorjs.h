/** LICENSE TEMPLATE */

#include "mdbjs/jsobject.h"
#include "supervisor.h"

namespace mdb::js {
struct Supervisor : public PtrJsObject<mdb::js::Supervisor, mdb::TraceeController, StringLiteral{"Supervisor"}>
{
  enum Slots
  {
    ThisPointer,
    SlotCount
  };

  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  static bool js_to_string(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static constexpr JSFunctionSpec FunctionSpec[] = {JS_FN("id", &js_id, 0, 0),
                                                    JS_FN("toString", &js_to_string, 0, 0), JS_FS_END};

  // Uncomment when you want to define properties
  // static constexpr JSPropertySpec PropertiesSpec[]{JS_PS_END};
};
} // namespace mdb::js