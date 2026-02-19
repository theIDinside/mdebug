/** LICENSE TEMPLATE */
#include "bpjs.h"

// mdb
#include <events/stop_event.h>
#include <mdbjs/jsobject.h>
#include <mdbjs/mdbjs.h>
#include <mdbjs/taskinfojs.h>
#include <mdbjs/util.h>
#include <tracer.h>
#include <utils/logger.h>
#include <utils/todo.h>

// dependency
#include <mdbjs/include-quickjs.h>

namespace mdb::js {

JsBreakpointFunction::~JsBreakpointFunction() noexcept
{
  if (!JS_IsUndefined(mFunctionObject)) {
    JS_FreeValue(mContext, mFunctionObject);
  }
}

/* static */
std::expected<std::unique_ptr<JsBreakpointFunction>, JavascriptException>
JsBreakpointFunction::CreateJsBreakpointFunction(JSContext *cx, std::string_view sourceCode) noexcept
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
  std::memset(buf, 0, std::size(buf));
  auto end = std::format_to(buf, R"(this.bpfun1 = function(bpstat, task) {{{}}};)", sourceCode);

  std::string_view fnString{ buf, end };
  DBGLOG(core, "Evaluating source code: '{}'", fnString);
  MDB_ASSERT(!JS_HasException(cx), "Context must not have pending exception before evaluating new script.");

  StackValue eval = StackValue::Eval(cx, fnString.data(), fnString.size(), "<bpcondition>", JS_EVAL_TYPE_GLOBAL);
  StackValue global = StackValue::GetGlobal(cx);
  StackValue compiledValue = global.GetPropertyString("bpfun1");

  if (auto exception = JavascriptException::GetException(cx); exception) {
    JS_FreeValue(cx, compiledValue);
    auto &exc = *exception;
    DBGLOG(warning,
      "Could not evaluate javascript, exception: {}\nStack trace:\n{}",
      exc.mExceptionMessage,
      exc.mStackTrace);
    return std::unexpected(std::move(exception.value()));
  }

  MDB_ASSERT(JS_IsFunction(cx, compiledValue), "Must become a function but evaluation produced something else");
  return std::make_unique<JsBreakpointFunction>(cx, compiledValue.Release());
}

bool
JsBreakpointFunction::Run(BreakpointHitEventResult *breakpointStatus, TaskInfo &task) noexcept
{
  PROFILE_SCOPE("JsBreakpointFunction::Run", logging::kInterpreter);
  DBGLOG(interpreter, "calling breakpoint function");

  JsBreakpointEvent bpEvent = JsBreakpointEvent::CreateBinding(mContext, breakpointStatus);
  JsTaskInfo taskInfo = JsTaskInfo::CreateBinding(mContext, RefPtr{ &task });

  JSValue args[2]{ bpEvent, taskInfo };

  auto result = CallFunction(mContext, mFunctionObject, JS_UNDEFINED, args);
  if (result.has_value()) {
    JS_FreeValue(mContext, *result);
    return true;
  }
  auto err = std::move(result).error();
  DBGLOG(warning, "Conditional breakpoint fn failed: {}", err.mExceptionMessage);

  return false;
}

std::unique_ptr<QuickJsString>
JsBreakpointFunction::EvaluateLog(TaskInfo *taskInfo, UserBreakpoint *breakpoint) noexcept
{
  TODO("Implement");
  (void)taskInfo;
  (void)breakpoint;
  return nullptr;
}

auto
JsBreakpoint::Id(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) -> JSValue
{
  auto pointer = GetThisOrReturnException(pointer, "Invalid breakpoint!");
  return JS_NewUint32(cx, pointer->mId);
}

auto
JsBreakpoint::Enable(JSContext *cx, [[maybe_unused]] JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) -> JSValue
{
  return JS_ThrowTypeError(cx, "Enable method not implemented");
};

auto
JsBreakpoint::Disable(JSContext *cx, [[maybe_unused]] JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) -> JSValue
{
  return JS_ThrowTypeError(cx, "Disable method not implemented");
};

auto
JsBreakpoint::ToString(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv)) -> JSValue
{
  auto pointer = GetThisOrReturnException(pointer, "Invalid breakpoint!");
  Ref<BreakpointLocation> bpLoc = pointer->GetLocation();
  const LocationSourceInfo *slocInfo = bpLoc ? bpLoc->GetSourceLocationInfo() : nullptr;
  char buf[1024];
  char *end = buf;
  if (slocInfo) {
    end = std::format_to(buf,
      R"("{{ id":{}, "kind":"{}", "loc":"{}", "source": "{}:{}" }})",
      pointer->mId,
      pointer->mKind,
      bpLoc ? bpLoc->Address() : AddrPtr{ nullptr },
      slocInfo->mSourceFile,
      slocInfo->mLineNumber);
  } else {
    end = std::format_to(buf,
      R"({{ "id":{}, "kind":"{}", "loc":"{}" }})",
      pointer->mId,
      pointer->mKind,
      bpLoc ? bpLoc->Address() : AddrPtr{ nullptr });
  }

  auto len = std::distance(buf, end);
  MDB_ASSERT(len <= 1024, "Stack space written over");
  auto strValue = JS_NewStringLen(cx, buf, len);
  return strValue;
}

JSValue
JsBreakpointEvent::Stop(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *bpEvent = GetThisOrReturnException(bpEvent, "Could not get Breakpoint status");

  int choice = 0;

  if (argCount > 0) {
    if (!JS_IsNumber(argv[0])) {
      // TODO: Hook up with user notificaiton system so that they can be explicitly notified of a failing condition
      // evaluator.
      return JS_ThrowTypeError(cx,
        "Argument to stop() must be a number, ranging between values 0 .. 2. 0=stop task, 1=stop all, 2=resume");
    }

    choice = JS_ToInt32(cx, &choice, argv[0]);
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
JsBreakpointEvent::Retire(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *status = GetThisOrReturnException(status, "Could not get Breakpoint status");
  status->mRetireBreakpoint = BreakpointOp::Retire;
  return JS_UNDEFINED;
}

} // namespace mdb::js