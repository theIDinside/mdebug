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

template <typename Out, typename TaskT>
constexpr Out
ToString(Out iteratorLike, const TaskT &task)
{
  return fmt::format_to(iteratorLike, "thread {}.{}, dbg id={}: stopped={}", task.GetTaskLeaderTid().value_or(-1),
                        task.mTid, task.mSessionId, task.IsStopped());
}

struct TaskInfo : public RefPtrJsObject<mdb::js::TaskInfo, mdb::TaskInfo, StringLiteral{"Task"}>
{
  enum Slots
  {
    ThisPointer,
    SlotCount
  };

  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  static bool js_pc(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  static bool js_frame(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  static bool js_to_string(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static constexpr JSFunctionSpec FunctionSpec[] = {JS_FN("id", &js_id, 0, 0), JS_FN("pc", &js_pc, 0, 0),
                                                    JS_FN("frame", &js_frame, 1, 0),
                                                    JS_FN("toString", &js_to_string, 0, 0), JS_FS_END};

  // Uncomment when you want to define properties
  // static constexpr JSPropertySpec PropertiesSpec[]{JS_PS_END};
};

} // namespace mdb::js

namespace mdb {
using JSTaskInfo = mdb::js::TaskInfo;
}