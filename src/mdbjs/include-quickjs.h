/** LICENSE TEMPLATE */
#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type-mismatch"

#include <quickjs/quickjs.h>

#pragma GCC diagnostic pop
#pragma GCC diagnostic pop

#ifndef JS_UNUSED
#define JS_UNUSED_ARGS(argCount, argv) [[maybe_unused]] int argCount, [[maybe_unused]] JSValue *argv
#define JS_ARGV(argCount, argv) int argCount, JSValue *argv
#endif