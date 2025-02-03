/** LICENSE TEMPLATE */
#include "supervisorjs.h"

namespace mdb::js {

/* static */
bool
Supervisor::js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto supervisor = Get(callee.get());

  args.rval().setInt32(supervisor->TaskLeaderTid());
  return true;
}

/* static */
bool
Supervisor::js_to_string(JSContext *cx, unsigned argc, JS ::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto supervisor = Get(callee);
  char buf[512];
  auto it = ToString(buf, supervisor);
  *it = 0;
  auto length = std::distance(buf, it + 1);
  // Define your custom string representation
  JSString *str = JS_NewStringCopyN(cx, buf, length);
  if (!str) {
    return false;
  }

  args.rval().setString(str);
  return true;
}

} // namespace mdb::js