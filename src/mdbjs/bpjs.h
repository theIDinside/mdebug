/** LICENSE TEMPLATE */
#pragma once
#include "bp.h"
#include "mdbjs/jsobject.h"
#include "mdbjs/util.h"
#include "quickjs/quickjs.h"
#include <common/typedefs.h>
#include <span>

#define CFunctionEntry(Type, Fn, Name, ArgCount) JS_CFUNC_DEF(Name, ArgCount, JsBreakpoint::Fn)

namespace mdb::js {

struct JsBreakpointFunction
{
  JSContext *mContext;
  JSValue mFunctionObject;

  ~JsBreakpointFunction() noexcept;

  /**
   * Source the `sourceCode` as a function to be called when a breakpoint is hit. One parameter is available to the
   * source code, called `bpstat` which is a breakpoint status that can be manipulated to decide if a task should
   * stop (or if all tasks should stop, etc)
   */
  static std::expected<std::unique_ptr<JsBreakpointFunction>, QuickJsString> CreateJsBreakpointFunction(
    JSContext *mContext, std::string_view sourceCode) noexcept;

  /**
   * Runs the compiled breakpoint function. The Javascript code can set whether or not a task should stop, or all
   * tasks, or nothing should happen, by manipulating the `BreakpointStatus` object. See `JsBreakpointStatus` for
   * interface.
   * @returns - whether or not evaluation succeeeded.
   */
  bool Run(BreakpointHitEventResult *breakpointStatus) noexcept;

  std::unique_ptr<QuickJsString> EvaluateLog(TaskInfo *taskInfo, UserBreakpoint *breakpoint) noexcept;
};

struct JsBreakpoint : public JSBinding<JsBreakpoint, UserBreakpoint, JavascriptClasses::Breakpoint>
{
  static auto Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Enable(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Disable(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;

  static constexpr std::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr JSCFunctionListEntry funcs[] = { /** Method definitions */
      FunctionEntry("id", 0, &JsBreakpoint::Id),
      FunctionEntry("enable", 0, &JsBreakpoint::Enable),
      FunctionEntry("disable", 0, &JsBreakpoint::Disable),
      ToStringTag("Breakpoint")
    };
    return funcs;
  }
};

struct JsBreakpointEvent
    : public JSBinding<JsBreakpointEvent, BreakpointHitEventResult, JavascriptClasses::BreakpointStatus>
{
  static auto Stop(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;
  static auto Retire(JSContext *context, JSValue thisValue, int argCount, JSValue *argv) -> JSValue;

  static constexpr std ::span<const JSCFunctionListEntry>
  PrototypeFunctions() noexcept
  {
    static constexpr JSCFunctionListEntry funcs[] = {
      /** Method definitions */
      FunctionEntry("stop", 1, &JsBreakpointEvent::Stop),
      FunctionEntry("retire", 0, &JsBreakpointEvent::Retire),
      ToStringTag("BreakpointStatus"),
    };

    return std::span<const JSCFunctionListEntry>{ funcs };
  }
};

} // namespace mdb::js

#undef CFunctionEntry