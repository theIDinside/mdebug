/** LICENSE TEMPLATE */
#pragma once

#include <common/macros.h>

#define FOR_EACH_LOG(LOGCHANNEL)                                                                                  \
  LOGCHANNEL(core, "Debugger Core", "Messages that don't have a intuitive log channel can be logged here.")       \
  LOGCHANNEL(dap, "Debug Adapter Protocol", "Log messages involving the DA protocol should be logged here.")      \
  LOGCHANNEL(                                                                                                     \
    dwarf, "DWARF Debug Symbol Information", "Log messages involving symbol parsing and value evaluation")        \
  LOGCHANNEL(                                                                                                     \
    awaiter, "Wait Status Reading", "Log messages involving the wait status or wait-status adjacent systems")     \
  LOGCHANNEL(                                                                                                     \
    eh, "Exception Frame Header", "Log messages that involve unwinding and parsing unwind symbol information")    \
  LOGCHANNEL(remote, "GDB Remote Protocol", "Log messages related to the GDB Remote Protocol")                    \
  LOGCHANNEL(warning, "Warnings", "Unexpected behaviors should be logged to this chanel")                         \
  LOGCHANNEL(interpreter, "Debugger script interpreter", "Log interpreter related messages here")

ENUM_TYPE_METADATA(Channel, FOR_EACH_LOG, DEFAULT_ENUM, i8)