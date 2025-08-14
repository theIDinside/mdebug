/** LICENSE TEMPLATE */
#include "supervisorjs.h"
#include "mdbjs/bpjs.h"
#include "mdbjs/jsobject.h"
#include "quickjs/quickjs.h"

namespace mdb::js {

static constexpr auto OpaqueDataErrorMessage = "Could not retrieve supervisor";

/* static */
JSValue
JsSupervisor::Id(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *native = GetThisOrReturnException(native, OpaqueDataErrorMessage);

  return JS_NewInt32(context, native->TaskLeaderTid());
}
/* static */
JSValue
JsSupervisor::ToString(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *supervisor = GetThisOrReturnException(supervisor, OpaqueDataErrorMessage);

  char buf[512];
  auto ptr = std::format_to(buf,
    "supervisor {}: threads={}, exited={}",
    supervisor->TaskLeaderTid(),
    supervisor->GetThreads().size(),
    supervisor->IsExited());
  auto len = std::distance(buf, ptr);
  auto strValue = JS_NewStringLen(context, buf, len);

  return strValue;
}

template <typename T> struct Foo
{
  static int
  Create(T *t)
  {
    return 1;
  }
};

/* static */
JSValue
JsSupervisor::Breakpoints(JSContext *context, JSValue thisValue, int argCount, JSValue *argv)
{
  auto *supervisor = GetThisOrReturnException(supervisor, OpaqueDataErrorMessage);

  auto bps = supervisor->GetUserBreakpoints().AllUserBreakpoints();
  auto arrayObject = JS_NewArray(context);

  if (JS_IsUndefined(arrayObject)) {
    return JS_ThrowTypeError(context, "Created array was undefined");
  }

  if (JS_IsException(arrayObject)) {
    return JS_Throw(context, arrayObject);
  }

  for (const auto &[idx, bp] : std::ranges::enumerate_view{ bps }) {
    auto res = JsBreakpoint::CreateValue(context, bp);
    JS_SetPropertyUint32(context, arrayObject, idx, res);
  }

  return arrayObject;
}

} // namespace mdb::js