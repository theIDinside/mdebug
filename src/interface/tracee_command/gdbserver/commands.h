/** LICENSE TEMPLATE */
#pragma once
#include <string_view>

namespace mdb::gdb {

enum class Command
{
  EnableExtendedMode,
  InitialStopQuery,
};

struct CommandInfo
{
  std::string_view name;
  std::string_view packet_fmt_string;
  bool has_arguments;
  bool has_reply;
};

struct RemoteCommand
{
  Command cmd;
};

} // namespace mdb::gdb