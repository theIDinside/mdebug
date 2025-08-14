/** LICENSE TEMPLATE */
#include "bpjs.h"
#include "events/stop_event.h"
#include "mdbjs/jsobject.h"
#include "mdbjs/util.h"
#include "quickjs/quickjs.h"
#include "utils/logger.h"
#include <supervisor.h>
#include <tracer.h>

namespace mdb::js {

JsBreakpointFunction::~JsBreakpointFunction() noexcept
{
  if (!JS_IsUndefined(mFunctionObject)) {
    JS_FreeValue(mContext, mFunctionObject);
  }
}

/* static */
std::expected<std::unique_ptr<JsBreakpointFunction>, QuickJsString>
JsBreakpointFunction::CreateJsBreakpointFunction(JSContext *context, std::string_view sourceCode) noexcept
{
  static constexpr auto stackBufferSize = 4096;
  if (sourceCode.size() > 4096 - 64) {
    DBGLOG(warning,
      "Source code for breakpoint condition reaching beyond stack buffer size: {} > {}",
      sourceCode.size(),
      stackBufferSize);
    return nullptr;
  }

  char buf[stackBufferSize];
  auto end = std::format_to(buf, "(function(bpstat){{\n{}\n}})", sourceCode);

  std::string_view fnString{ buf, end };

  JSValue functionValue = JS_Eval(context, fnString.data(), fnString.size(), "<bpcondition>", JS_EVAL_TYPE_GLOBAL);
  if (JS_IsException(functionValue)) {
    JSValue exception = JS_GetException(context);
    auto qjsString = QuickJsString::FromValue(context, exception);
    JS_FreeValue(context, exception);
    JS_FreeValue(context, functionValue);
    DBGLOG(warning, "Could not evaluate javascript, exception: {}", qjsString.mString);
    return std::unexpected(std::move(qjsString));
  }

  return std::make_unique<JsBreakpointFunction>(context, functionValue);
}

bool
JsBreakpointFunction::Run(BreakpointHitEventResult *breakpointStatus) noexcept
{
  auto jsBpStatus = mdb::js::JsBreakpointEvent::CreateStackBoundValue(mContext, breakpointStatus);
  JSValue args[1]{ jsBpStatus.GetValue() };
  auto result = CallFunction(mContext, mFunctionObject, JS_UNDEFINED, args);
  if (result.has_value()) {
    JS_FreeValue(mContext, *result);
    return true;
  }
  auto err = std::move(result).error();
  DBGLOG(warning, "Conditional breakpoint fn failed: {}", err.mString);
  return false;
}

std::unique_ptr<QuickJsString>
JsBreakpointFunction::EvaluateLog(TaskInfo *taskInfo, UserBreakpoint *breakpoint) noexcept
{
  return nullptr;
}

auto
JsBreakpoint::Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue
{
  auto pointer = GetThisOrReturnException(pointer, "Invalid breakpoint!");
  return JS_NewUint32(context, pointer->mId);
}

auto
JsBreakpoint::Enable(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue
{
  return JS_ThrowTypeError(context, "Enable method not implemented");
};

auto
JsBreakpoint::Disable(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue
{
  return JS_ThrowTypeError(context, "Disable method not implemented");
};

JSValue
JsBreakpointEvent::Stop(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *bpEvent = GetThisOrReturnException(bpEvent, "Could not get Breakpoint status");

  bool stopTask = false;
  bool stopAll = false;

  int choice = 0;

  if (argCount > 0) {
    if (!JS_IsNumber(argv[0])) {
      // TODO: Hook up with user notificaiton system so that they can be explicitly notified of a failing condition
      // evaluator.
      return JS_ThrowTypeError(context,
        "Argument to stop() must be a number, ranging between values 0 .. 2. 0=stop task, 1=stop all, 2=resume");
    }

    choice = JS_ToInt32(context, &choice, argv[0]);
  }

  if (!(choice >= 0 && choice <= 2)) {
    DBGLOG(core, "Invalid choice reported by evaluator.");
    return JS_UNDEFINED;
  }

  switch (choice) {
  case 0:
    bpEvent->mResult = EventResult::Stop;
    break;
  case 1:
    bpEvent->mResult = EventResult::StopAll;
    break;
  case 2:
    bpEvent->mResult = EventResult::Resume;
    break;
  default:
    break;
  }

  return JS_UNDEFINED;
}

JSValue
JsBreakpointEvent::Retire(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *status = GetThisOrReturnException(status, "Could not get Breakpoint status");
  status->mRetireBreakpoint = BreakpointOp::Retire;
  return JS_UNDEFINED;
}

} // namespace mdb::js