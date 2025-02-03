/** LICENSE TEMPLATE */
#pragma once
#include "bp.h"
#include "mdbjs/jsobject.h"
#include "typedefs.h"
#include <cstring>

namespace mdb::js {
struct CompileBreakpointCallable
{
  JS::Heap<JSFunction *> mCompiledFunction;

  void trace(JSTracer *trc, const char *name);
  std::optional<EventResult> EvaluateCondition(JSContext *context, mdb::TaskInfo *task,
                                               mdb::UserBreakpoint *bp) noexcept;
  std::optional<std::string> EvaluateLog(JSContext *context, mdb::TaskInfo *task,
                                         mdb::UserBreakpoint *bp) noexcept;
};

struct Breakpoint : public RefPtrJsObject<mdb::js::Breakpoint, mdb::UserBreakpoint, StringLiteral{"Breakpoint"}>
{
  enum Slots
  {
    ThisPointer,
    SlotCount
  };

  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  // TODO(simon): implement
  static bool js_enable(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  static bool js_disable(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static constexpr JSFunctionSpec FunctionSpec[] = {JS_FN("id", &js_id, 0, 0), JS_FS_END};
  // Uncomment when you want to define properties
  // static constexpr JSPropertySpec PropertiesSpec[]{JS_PS_END};
};

} // namespace mdb::js