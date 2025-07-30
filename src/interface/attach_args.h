/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/typedefs.h>

// stdlib
#include <optional>
#include <string>
#include <variant>

namespace mdb {
enum class RemoteType
{
  RR,
  GDB
};

struct PtraceAttachArgs
{
  Pid pid;
};

struct GdbRemoteAttachArgs
{
  std::string host;
  int port;
  std::optional<Pid> pid{std::nullopt};
  bool allstop;
  RemoteType type;
};

struct AutoArgs
{
  Pid mExistingProcessId;
};

using AttachArgs = std::variant<PtraceAttachArgs, GdbRemoteAttachArgs, AutoArgs>;
} // namespace mdb