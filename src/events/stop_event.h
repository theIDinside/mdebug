#pragma once

#include "utils/macros.h"
#include <csignal>
#include <typedefs.h>
#include <utils/smartptr.h>
namespace mdb {
class TraceeController;
struct TaskInfo;
} // namespace mdb

#define FOR_EACH_EVENT(EACH_FN)                                                                                   \
  EACH_FN(stop, "Generic, unspecfied stop", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)       \
  EACH_FN(libraryEvent, "New libraries was added to the process space", void, mdb::TraceeController *,            \
          const mdb::Ref<mdb::TaskInfo> &)                                                                        \
  EACH_FN(breakpointHitEvent, "A breakpoint was hit", void, mdb::TraceeController *,                              \
          const mdb::Ref<mdb::TaskInfo> &, u32)                                                                   \
  EACH_FN(syscallEvent, "A syscall event happened", void, mdb::TraceeController *,                                \
          const mdb::Ref<mdb::TaskInfo> &, int, bool)                                                             \
  EACH_FN(threadCreated, "A new thread was created", void, mdb::TraceeController *,                               \
          const mdb::Ref<mdb::TaskInfo> &, Tid)                                                                   \
  EACH_FN(threadExited, "A thread exited", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)        \
  EACH_FN(watchpointEvent, "A watch point was triggered", void, mdb::TraceeController *,                          \
          const mdb::Ref<mdb::TaskInfo> &)                                                                        \
  EACH_FN(processExited, "A process exited", void, Pid)                                                           \
  EACH_FN(processTerminated, "A process terminated", void, Pid, int)                                              \
  EACH_FN(fork, "A process forked", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)               \
  EACH_FN(vFork, "A process vForked", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)             \
  EACH_FN(vForkDone, "A process is done vforking", void, mdb::TraceeController *,                                 \
          const mdb::Ref<mdb::TaskInfo> &)                                                                        \
  EACH_FN(exec, "The exec system call", void, int, std::string)                                                   \
  EACH_FN(clone, "The clone system call", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &, Tid)    \
  EACH_FN(deferToSupervisor, "A deferred event", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)  \
  EACH_FN(signal, "The task was signalled", void, int, int)                                                       \
  EACH_FN(stepped, "A task stepped", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)              \
  EACH_FN(entry, "A process is at entry", void, mdb::TraceeController *, const mdb::Ref<mdb::TaskInfo> &)         \
  EACH_FN(stoppedAll, "All tasks has been stopped by the supervisor", void, mdb::TraceeController *,              \
          const mdb::Ref<mdb::TaskInfo> &)

ENUM_TYPE_METADATA(StopEvents, FOR_EACH_EVENT, DEFAULT_ENUM)

#define ENUM_MAP(E, DESCRIPTION, ...)                                                                             \
  template <> struct StopEventsTraits<StopEvents::E>                                                              \
  {                                                                                                               \
    using TypeList = std::tuple<__VA_ARGS__>;                                                                     \
  };                                                                                                              \
  template <StopEvents Event> using ToFn = ToFunction<typename StopEventsTraits<Event>::TypeList>;

FOR_EACH_EVENT(ENUM_MAP)

#define FOR_EACH_EVENT_RESULT(RETURN_KIND)                                                                        \
  RETURN_KIND(None, "No value returned. Perform default behavior. For events like breakpoint hits, this usually " \
                    "means to notify user of a stop. For events like clone, it means resuming silently.")         \
  RETURN_KIND(Resume, "Don't halt the task that saw the current event")                                           \
  RETURN_KIND(Stop, "Stop task and don't resume until explicitly told to do so.")                                 \
  RETURN_KIND(StopAll, "Stop task, and also halt all other tasks in this process.")

ENUM_TYPE_METADATA(EventResult, FOR_EACH_EVENT_RESULT, DEFAULT_ENUM)

#define FOR_EACH_BP_OP(OP)                                                                                        \
  OP(Keep, "Keep the breakpoint")                                                                                 \
  OP(Retire, "Retire the breakpoint after this.")

ENUM_TYPE_METADATA(BreakpointOp, FOR_EACH_BP_OP, DEFAULT_ENUM)