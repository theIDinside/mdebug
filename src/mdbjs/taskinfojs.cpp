/** LICENSE TEMPLATE */
#include "taskinfojs.h"
#include "framejs.h"
#include "js/BigInt.h"
#include <supervisor.h>

namespace mdb::js {

/* static */
bool
TaskInfo::js_pc(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto task = Get(callee.get());

  JS::BigInt *bigInt = JS::NumberToBigInt(cx, task->GetRegisterCache().GetPc().GetRaw());
  if (!bigInt) {
    JS_ReportErrorASCII(cx, "Failed to create BigInt");
    return false;
  }

  args.rval().setBigInt(bigInt);
  return true;
}

bool
TaskInfo::js_frame(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto task = Get(callee.get());
  auto &callStack = task->GetSupervisor()->BuildCallFrameStack(*task, CallStackRequest::full());
  auto frame = callStack.GetFrameAtLevel(0);

  JS::Rooted<JSObject *> frameJs{
    cx, mdb::js::Frame::Create(cx, Ref<FrameLookupHandle>{new FrameLookupHandle{task, *frame}})};
  args.rval().setObject(*frameJs);

  return true;
}

/* static */
bool
TaskInfo::js_to_string(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  char buf[512];
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto task = Get(callee.get());
  auto it = ToString(buf, *task);
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