/** LICENSE TEMPLATE */
#pragma once

#include "../../utils/macros.h"
#include <cstdint>
#include <string_view>

namespace mdb::ui::dap {

enum class CommandType : std::uint8_t
{
#define DAP_COMMANDS
#define ITEM(name, value) name = value,
#include "dap.defs"
#undef ITEM
#undef DAP_COMMANDS
  UNKNOWN
};

constexpr std::string_view
to_str(CommandType command) noexcept
{
#define DAP_COMMANDS
#define ITEM(name, value)                                                                                         \
  case CommandType::name:                                                                                         \
    return #name;
  switch (command) {
#include "dap.defs"
  case CommandType::UNKNOWN:
    return "Unknown command type";
  }
#undef ITEM
#undef DAP_COMMANDS
  return "Unknown command type";
}

// We sent events, we never receive them, so an "UNKNOWN" value is unnecessary.
// or better put; Events are an "output" type only.
enum class Events : std::uint8_t
{
#define DAP_EVENTS
#define ITEM(name, value) name = value,
#include "dap.defs"
#undef ITEM
#undef DAP_EVENTS
};

constexpr std::string_view
to_str(Events command) noexcept
{
#define DAP_EVENTS
#define ITEM(name, value)                                                                                         \
  case Events::name:                                                                                              \
    return #name;
  switch (command) {
#include "dap.defs"
  }
#undef ITEM
#undef DAP_EVENTS
}

enum class ProtocolMessageType : std::uint8_t
{
#define DAP_PROTOCOL_MESSAGE
#define ITEM(name, value) name = value,
#include "dap.defs"
#undef ITEM
#undef DAP_PROTOCOL_MESSAGE
};

constexpr std::string_view
to_str(ProtocolMessageType msg) noexcept
{
#define DAP_PROTOCOL_MESSAGE
#define ITEM(name, value)                                                                                         \
  case ProtocolMessageType::name:                                                                                 \
    return #name;
  switch (msg) {
#include "dap.defs"
  }
#undef ITEM
#undef DAP_PROTOCOL_MESSAGE
}

enum class StoppedReason : std::uint8_t
{
#define DAP_STOPPED_REASON
#define ITEM(name, value) name = value,
#include "dap.defs"
#undef ITEM
#undef DAP_STOPPED_REASON
};

constexpr std::string_view
to_str(StoppedReason reason) noexcept
{
  switch (reason) {
  case StoppedReason::Step:
    return "step";
  case StoppedReason::Breakpoint:
    return "breakpoint";
  case StoppedReason::Exception:
    return "exception";
  case StoppedReason::Pause:
    return "pause";
  case StoppedReason::Entry:
    return "entry";
  case StoppedReason::Goto:
    return "goto";
  case StoppedReason::FunctionBreakpoint:
    return "function breakpoint";
  case StoppedReason::DataBreakpoint:
    return "data breakpoint";
  case StoppedReason::InstructionBreakpoint:
    return "instruction breakpoint";
  }
  MIDAS_UNREACHABLE
}

// unfortunately, the DAP people were so "brilliant" as to not make the names
// source code friendly. Amazing. Therefore we need to either hand roll them like this
// or write a generator that takes names like this and turns them into the un-sourcecode friendly versions
enum class ThreadReason : std::uint8_t
{
  Started,
  Exited
};

constexpr std::string_view
to_str(ThreadReason reason) noexcept
{
  switch (reason) {
  case ThreadReason::Started:
    return "started";
  case ThreadReason::Exited:
    return "exited";
    break;
  }
  MIDAS_UNREACHABLE
}

} // namespace mdb::ui::dap