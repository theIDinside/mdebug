/** LICENSE TEMPLATE */
#include "taskinfojs.h"

// mdb
#include <interface/tracee_command/supervisor_state.h>
#include <mdbjs/framejs.h>
#include <mdbjs/jsobject.h>
#include <symbolication/callstack.h>

namespace mdb::js {

static constexpr auto TaskInfoOpaqueDataErrorMessage = "Could not retrieve task info";

/*static*/ JSValue
JsTaskInfo::Id(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  auto id = JS_NewInt32(cx, taskInfo->mTid);
  return id;
}

/*static*/ JSValue
JsTaskInfo::Pc(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  return JS_NewBigUint64(cx, taskInfo->GetPc().GetRaw());
}
/*static*/ JSValue
JsTaskInfo::Frame(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv)
{
  PROFILE_SCOPE("JsTaskInfo::Frame", logging::kInterpreter);
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  auto supervisor = taskInfo->GetSupervisor();

  if (!supervisor) {
    return JS_ThrowTypeError(cx, "Could not retrieve supervisor for task");
  }

  i64 frameLevel = 0;

  if (argCount != 0) {
    if (!JS_ToInt64(cx, &frameLevel, argv[0])) {
      return JS_ThrowTypeError(cx, "Argument to .frame() must be an integer (or no argument, for level 0)");
    }
    if (frameLevel < 0) {
      return JS_ThrowTypeError(cx, "Valid frame values are 0 .. N");
    }
  }

  auto &callStack = supervisor->BuildCallFrameStack(*taskInfo, CallStackRequest::full());
  auto frame = callStack.GetFrameAtLevel(static_cast<u32>(frameLevel));
  const auto result = JsFrame::CreateValue(cx, RefPtr{ new FrameLookupHandle{ RefPtr{ taskInfo }, *frame } });
  return result;
}

/*static*/ JSValue
JsTaskInfo::ToString(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
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
  auto strValue = JS_NewStringLen(cx, buf, len);
  return strValue;
}

/*static*/ JSValue
JsTaskInfo::Resume(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *taskInfo = GetThisOrReturnException(taskInfo, TaskInfoOpaqueDataErrorMessage);

  if (!taskInfo->IsValid()) {
    return JS_ThrowTypeError(cx, "Can't resume task, task is invalid");
  }

  auto supervisor = taskInfo->GetSupervisor();
  supervisor->ResumeTask(*taskInfo, tc::RunType::Continue);
  return JS_UNDEFINED;
}

} // namespace mdb::js