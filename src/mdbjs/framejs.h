/** LICENSE TEMPLATE */
#pragma once

#include "mdbjs/jsobject.h"
#include "symbolication/callstack.h"
#include "task.h"
#include "utils/smartptr.h"
#include <common/typedefs.h>
#include <cstring>

namespace mdb {
struct FrameLookupHandle
{
  INTERNAL_REFERENCE_COUNT(FrameLookupHandle);

public:
  Ref<TaskInfo> mTask;
  // sym::Frame is a "cheap" (trivially copyable) type for a reason. It's not meant to hold state (like gdb does
  // where frame is an actual type that's responsible for a bunch of state and historically has had many, many
  // bugs). It's meant to identify a stack frame. Using this object, we can iterate `mTask`s callstack and see if
  // any matches `mFrame`, if they do, we know we can do frame operations using this frame as a sort of "key".
  sym::Frame mFrame;

  FrameLookupHandle(Ref<TaskInfo> task, sym::Frame frame) noexcept : mTask(std::move(task)), mFrame(frame) {}
  bool IsValid() noexcept;
};
}; // namespace mdb

namespace mdb::js {
struct Frame : public RefPtrJsObject<mdb::js::Frame, mdb::FrameLookupHandle, StringLiteral{"Frame"}>
{
  enum Slots
  {
    ThisPointer,
    SlotCount
  };

  /** Return the variables reference (id) for this frame object. */
  static bool js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  /** Return the local variables of this frame. */
  static bool js_locals(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  /** Return the arguments passed to this frame. */
  static bool js_arguments(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  /** Return frame object that called this frame. */
  static bool js_caller(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;
  /** Return the name of the function (if it has any). */
  static bool js_name(JSContext *cx, unsigned argc, JS::Value *vp) noexcept;

  static constexpr JSFunctionSpec FunctionSpec[] = {
    JS_FN("id", &js_id, 0, 0),         JS_FN("locals", &js_locals, 0, 0), JS_FN("arguments", &js_arguments, 0, 0),
    JS_FN("caller", &js_caller, 0, 0), JS_FN("name", &js_name, 0, 0),     JS_FS_END};
  // Uncomment when you want to define properties
  // static constexpr JSPropertySpec PropertiesSpec[]{JS_PS_END};
};
} // namespace mdb::js