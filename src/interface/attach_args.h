/** LICENSE TEMPLATE */
#pragma once
#include <optional>
#include <string>
#include <typedefs.h>
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