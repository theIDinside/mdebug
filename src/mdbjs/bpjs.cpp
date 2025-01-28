#include "bpjs.h"

namespace mdb::js {
void
CompiledBreakpointCondition::trace(JSTracer *trc, const char *name)
{
  JS::TraceEdge(trc, &mCompiledFunction, "breakpoint condition");
}
} // namespace mdb::js