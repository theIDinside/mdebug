/** LICENSE TEMPLATE */
#pragma once
#include "bp.h"
#include "js/CallArgs.h"
#include "js/PropertySpec.h"
#include "js/RootingAPI.h"
#include "mdbjs/jsobject.h"
#include "supervisor.h"
#include "typedefs.h"
#include "utils/smartptr.h"
#include <cstring>

namespace mdb::js {
struct CompiledBreakpointCondition
{
  JS::Heap<JSFunction *> mCompiledFunction;

  void trace(JSTracer *trc, const char *name);
  std::optional<EventResult> Evaluate(JSContext *context, mdb::TaskInfo *task, mdb::UserBreakpoint *bp) noexcept;
};

struct Breakpoint : public RefPtrJsObject<mdb::js::Breakpoint, mdb::UserBreakpoint, StringLiteral{"Breakpoint"}>
{
  enum Slots
  {
    ThisPointer,
    SlotCount
  };

  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static constexpr JSFunctionSpec FunctionSpec[] = {JS_FN("id", &js_id, 0, 0), JS_FS_END};
  // Uncomment when you want to define properties
  // static constexpr JSPropertySpec PropertiesSpec[]{JS_PS_END};
};

} // namespace mdb::js