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

struct PtraceAttachArgs
{
  Pid pid;
};

struct GdbRemoteAttachArgs
{
  std::string_view host;
  int port;
  std::optional<Pid> pid{ std::nullopt };
  bool allstop;
  RemoteType type;
};

struct AutoArgs
{
  Pid mExistingProcessId;
};

using AttachArgs = std::variant<PtraceAttachArgs, GdbRemoteAttachArgs, AutoArgs>;
} // namespace mdb