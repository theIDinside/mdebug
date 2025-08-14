/** LICENSE TEMPLATE */
#include "taskinfojs.h"

#include <mdbjs/framejs.h>
#include <mdbjs/jsobject.h>
#include <quickjs/quickjs.h>
#include <supervisor.h>

namespace mdb::js {

static constexpr auto TaskInfoOpaqueDataErrorMessage = "Could not retrieve task info";

/*static*/ JSValue
JsTaskInfo::Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  auto id = JS_NewInt32(context, taskInfo->mTid);
  return id;
}

/*static*/ JSValue
JsTaskInfo::Pc(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  return JS_NewBigUint64(context, taskInfo->GetRegisterCache().GetPc().GetRaw());
}
/*static*/ JSValue
JsTaskInfo::Frame(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  auto supervisor = taskInfo->GetSupervisor();

  if (!supervisor) {
    return JS_ThrowTypeError(context, "Could not retrieve supervisor for task");
  }

  i64 frameLevel = 0;

  if (argCount != 0) {
    if (!JS_ToInt64(context, &frameLevel, argv[0])) {
      return JS_ThrowTypeError(context, "Argument to .frame() must be an integer (or no argument, for level 0)");
    }
    if (frameLevel < 0) {
      return JS_ThrowTypeError(context, "Valid frame values are 0 .. N");
    }
  }

  auto &callStack = supervisor->BuildCallFrameStack(*taskInfo, CallStackRequest::full());
  auto frame = callStack.GetFrameAtLevel(static_cast<u32>(frameLevel));
  const auto result = Frame::CreateValue(context, RefPtr{ new FrameLookupHandle{ RefPtr{ taskInfo }, *frame } });
  return result;
}

/*static*/ JSValue
JsTaskInfo::ToString(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  char buf[512];
  auto ptr = std::format_to(buf,
    "thread {}.{}, dbg id={}: stopped={}",
    taskInfo->GetTaskLeaderTid().value_or(-1),
    taskInfo->mTid,
    taskInfo->mSessionId,
    taskInfo->IsStopped());
  auto len = std::distance(buf, ptr);
  auto strValue = JS_NewStringLen(context, buf, len);
  return strValue;
}

} // namespace mdb::js