// THIS IS NOT A HEADER FILE, REALLY. DO _NOT_ INCLUDE ANYWHERE BUT main.cpp

#include <mdbjs/bpjs.h>
#include <mdbjs/framejs.h>
#include <mdbjs/jsobject.h>
#include <mdbjs/supervisorjs.h>
#include <mdbjs/taskinfojs.h>
#include <mdbjs/variablejs.h>

namespace mdb::js {
// Run time registering the types
FOR_EACH_TYPE(REGISTER_TYPE);
} // namespace mdb::js