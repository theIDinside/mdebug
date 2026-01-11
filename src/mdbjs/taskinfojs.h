/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <mdbjs/jsobject.h>
#include <task.h>

namespace mdb::js {

template <typename Out, typename TaskT>
constexpr Out
ToString(Out iteratorLike, const TaskT &entry)
{
  return std::format_to(iteratorLike,
    "thread {}.{}, dbg id={}: stopped={}, valid={}",
    entry.mTask->GetTaskLeaderTid().value_or(-1),
    entry.mTid,
    entry.mTask->mSessionId,
    entry.mTask->IsStopped(),
    entry.mTask->IsValid());
}

struct JsTaskInfo : public JSBinding<JsTaskInfo, TaskInfo, JavascriptClasses::TaskInfo>
{
  static auto Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Pc(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Frame(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto ToString(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Resume(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr JSCFunctionListEntry funcs[]{ /** Method definitions */
      FunctionEntry("id", 0, &Id),
      FunctionEntry("pc", 0, &Pc),
      FunctionEntry("frame", 1, &Frame),
      FunctionEntry("toString", 0, &ToString),
      FunctionEntry("resume", 0, &Resume),
      ToStringTag("TaskInfo")
    };
    return funcs;
  }
};

} // namespace mdb::js
