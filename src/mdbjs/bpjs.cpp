/** LICENSE TEMPLATE */
#include "bpjs.h"
#include "bp.h"
#include "events/stop_event.h"
#include "js/CallAndConstruct.h"
#include "js/Exception.h"
#include "js/TypeDecls.h"
#include "js/ValueArray.h"
#include "mdbjs/mdbjs.h"
#include "mdbjs/taskinfojs.h"
#include "task.h"
#include <tracer.h>

namespace mdb::js {
void
CompiledBreakpointCondition::trace(JSTracer *trc, const char *name)
{
  JS::TraceEdge(trc, &mCompiledFunction, "breakpoint condition");
}

std::optional<EventResult>
CompiledBreakpointCondition::Evaluate(JSContext *cx, mdb::TaskInfo *task, mdb::UserBreakpoint *bp) noexcept
{
  JS::Rooted<JSFunction *> fn{cx, mCompiledFunction};
  JS::RootedValue rval(cx);

  // Prepare the arguments (two integers) and ensure they are rooted
  // Prepare the arguments
  JS::RootedValueArray<3> args{cx};

  JS::Rooted<JSObject *> jsTask{cx, mdb::js::TaskInfo::Create(cx, Ref<mdb::TaskInfo>{task})};
  JS::Rooted<JSObject *> jsBp{cx, mdb::js::Breakpoint::Create(cx, Ref<mdb::UserBreakpoint>{bp})};
  auto bp1 = mdb::js::Breakpoint::Create(cx, Ref<mdb::UserBreakpoint>{bp});
  args[0].setInt32(task->GetSupervisor()->TaskLeaderTid());
  args[1].setObject(*jsTask);
  args[2].setObject(*bp1);

  JS::HandleFunction f{fn};
  std::string err;
  const auto r = Tracer::GetScriptingInstance().CallFunction<int>(f, args, err);
  if (!r) {
    DBGLOG(interpreter, "CallFunction failure: {}", err);
    return {};
  }
  return Enum<EventResult>::FromInt(r.value());
}

/* static */
bool
Breakpoint::js_id(JSContext *cx, unsigned argc, JS::Value *vp) noexcept
{
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  JS::RootedObject callee(cx, &args.thisv().toObject());
  auto bp = Get(callee.get());
  if (bp) {
    args.rval().setInt32(bp->mId);
    return true;
  } else {
    JS_ReportErrorASCII(cx, "Breakpoint was undefined");
    return false;
  }
}

} // namespace mdb::js