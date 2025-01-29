/** LICENSE TEMPLATE */
#include "taskinfojs.h"

namespace mdb::js {
/* static */
bool
TaskInfo::js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto bp = Get(callee.get());
  if (bp) {
    args.rval().setInt32(bp->mTid);
    return true;
  } else {
    JS_ReportErrorASCII(cx, "Breakpoint was undefined");
    return false;
  }
}

} // namespace mdb::js