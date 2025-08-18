// THIS IS NOT A HEADER FILE, REALLY. DO _NOT_ INCLUDE ANYWHERE BUT main.cpp

#include <mdbjs/bpjs.h>
#include <mdbjs/framejs.h>
#include <mdbjs/jsobject.h>
#include <mdbjs/supervisorjs.h>
#include <mdbjs/taskinfojs.h>
#include <mdbjs/variablejs.h>

namespace mdb::js {
REGISTER_TYPE(JsBreakpointEvent);
REGISTER_TYPE(JsBreakpoint);
REGISTER_TYPE(Frame);
REGISTER_TYPE(JsSupervisor);
REGISTER_TYPE(JsTaskInfo);
REGISTER_TYPE(JsVariable);
} // namespace mdb::js