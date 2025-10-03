/** LICENSE TEMPLATE */
#pragma once

#include <common/macros.h>
#include <common/typedefs.h>

#define FOR_EACH_STOP_KIND(STOP_KIND)                                                                             \
  STOP_KIND(Stopped)                                                                                              \
  STOP_KIND(Execed)                                                                                               \
  STOP_KIND(Exited)                                                                                               \
  STOP_KIND(Forked)                                                                                               \
  STOP_KIND(VForked)                                                                                              \
  STOP_KIND(VForkDone)                                                                                            \
  STOP_KIND(Cloned)                                                                                               \
  STOP_KIND(Signalled)                                                                                            \
  STOP_KIND(SyscallEntry)                                                                                         \
  STOP_KIND(SyscallExit)                                                                                          \
  STOP_KIND(NotKnown)

ENUM_TYPE_METADATA(StopKind, FOR_EACH_STOP_KIND, DEFAULT_ENUM, u8)

namespace mdb {

struct StopStatus
{
  StopKind ws;
  union
  {
    int uStopExitCode;
    int uStopSignal;
  };
};

struct WaitPidResult
{
  Tid tid;
  StopStatus ws;
};

/** C++-ified result from waitpid syscall. */
struct WaitPid
{
  Tid tid;
  int status;
};

} // namespace mdb