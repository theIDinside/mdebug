/** LICENSE TEMPLATE */

#include "supervisorjs.h"

// mdb
#include <mdbjs/bpjs.h>
#include <mdbjs/jsobject.h>

// dependency
#include <mdbjs/include-quickjs.h>

namespace mdb::js {

static constexpr auto OpaqueDataErrorMessage = "Could not retrieve supervisor";

/* static */
JSValue
JsSupervisor::Id(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *native = GetThisOrReturnException(native, OpaqueDataErrorMessage);
  return JS_NewInt32(cx, native->TaskLeaderTid());
}
/* static */
JSValue
JsSupervisor::ToString(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *supervisor = GetThisOrReturnException(supervisor, OpaqueDataErrorMessage);

  char buf[512];
  auto ptr = std::format_to(buf,
    "supervisor {}: threads={}, exited={}",
    supervisor->TaskLeaderTid(),
    supervisor->ThreadsCount(),
    supervisor->IsExited());
  auto len = std::distance(buf, ptr);
  auto strValue = JS_NewStringLen(cx, buf, len);

  return strValue;
}

/* static */
JSValue
JsSupervisor::Breakpoints(JSContext *cx, JSValue thisValue, JS_UNUSED_ARGS(argCount, argv))
{
  auto *supervisor = GetThisOrReturnException(supervisor, OpaqueDataErrorMessage);

  auto bps = supervisor->GetUserBreakpoints().AllUserBreakpoints();
  auto arrayObject = JS_NewArray(cx);

  if (JS_IsUndefined(arrayObject)) {
    return JS_ThrowTypeError(cx, "Created array was undefined");
  }

  if (JS_IsException(arrayObject)) {
    return JS_Throw(cx, arrayObject);
  }

  for (const auto &[idx, bp] : std::ranges::enumerate_view{ bps }) {
    auto res = JsBreakpoint::CreateValue(cx, bp);
    JS_SetPropertyUint32(cx, arrayObject, idx, res);
  }

  return arrayObject;
}

/* static */
JSValue
JsSupervisor::ResumeAll(JSContext *cx, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *supervisor = GetThisOrReturnException(supervisor, OpaqueDataErrorMessage);

  supervisor->ResumeTarget(tc::RunType::Continue);
  return JS_UNDEFINED;
}

} // namespace mdb::js