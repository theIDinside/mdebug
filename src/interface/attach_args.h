#pragma once
#include <optional>
#include <string>
#include <typedefs.h>
#include <variant>

struct PtraceAttachArgs
{
  Pid pid;
};

struct GdbRemoteAttachArgs
{
  std::string host;
  int port;
  // Why pid == nullopt? Because.
  std::optional<Pid> pid{std::nullopt};
  bool allstop;
};

using AttachArgs = std::variant<PtraceAttachArgs, GdbRemoteAttachArgs>;