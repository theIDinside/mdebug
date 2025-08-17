/** LICENSE TEMPLATE */
#pragma once
#include <cstdint>

namespace mdb {

enum class BreakpointBehavior
{
  StopAllThreadsWhenHit,
  StopOnlyThreadThatHit
};

enum class BreakpointRequestKind : std::uint8_t
{
  source,
  function,
  instruction,
  data,
  exception,
};

enum class LocationUserKind : std::uint8_t
{
  Address,
  Source,
  Function,
  FinishFunction,
  LogPoint,
  ResumeTo,
  SharedObjectLoaded,
  Exception,
  LongJump
};
} // namespace mdb