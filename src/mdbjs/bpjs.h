#pragma once
#include "bp.h"
#include "js/Class.h"
#include "js/Object.h"
#include "js/RootingAPI.h"
#include "jsapi.h"
#include "mdbjs/jsobject.h"
#include "typedefs.h"
#include "utils/smartptr.h"
#include <type_traits>

namespace mdb::js {
struct CompiledBreakpointCondition
{
  u32 breakpointId;
  JS::Heap<JSFunction *> mCompiledFunction;

  void trace(JSTracer *trc, const char *name);
};

struct Breakpoint : public RefPtrObject<mdb::UserBreakpoint, StringLiteral{"Breakpoint"}>
{
};

} // namespace mdb::js