/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/typedefs.h>

// stdlib
#include <optional>
#include <variant>

namespace mdb {
enum class RemoteType : u8
{
  RR,
  GDB
};

// There's no "normal attach" configuration for RR, since that doesn't make sense. There are no free-running
// instances of RR replays in the world of MDB. Because we control them directly, locally in the debugger process.

struct PtraceAttachArgs
{
  Pid pid;
};

struct RRAttachArgs
{
  Pid pid;
};

using AttachArgs = std::variant<PtraceAttachArgs, RRAttachArgs>;
} // namespace mdb