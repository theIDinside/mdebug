/** LICENSE TEMPLATE */
#pragma once

#include "mdbjs/jsobject.h"
#include "quickjs/quickjs.h"
#include "symbolication/callstack.h"
#include "task.h"
#include "utils/smartptr.h"
#include <common/typedefs.h>

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

struct Frame : public JSBinding<Frame, mdb::FrameLookupHandle, JavascriptClasses::Frame>
{
  static auto Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Locals(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Arguments(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Caller(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Name(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr JSCFunctionListEntry funcs[]{ /** Method definitions */
      FunctionEntry("id", 0, &Id),
      FunctionEntry("locals", 0, &Locals),
      FunctionEntry("arguments", 0, &Arguments),
      FunctionEntry("caller", 0, &Caller),
      FunctionEntry("name", 0, &Name),
      ToStringTag("Frame")
    };
    return funcs;
  }
};

} // namespace mdb::js