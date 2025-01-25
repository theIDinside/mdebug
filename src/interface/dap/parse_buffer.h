/** LICENSE TEMPLATE */
#pragma once
#include "../../common.h"
#include "dap_defs.h"
#include <memory_resource>
#include <regex>
#include <typedefs.h>
#include <utility>

namespace ui::dap {
using namespace std::string_view_literals;
/* I've actually benchmarked this, and this is faster than a naive constexpr-map *and* a std::unordered_map
 * lookup by a *LARGE* margin. As such I see no good reason at all to change this as the DA-protocol is well
 * defined when it comes to it's commands. Any change to the spec will trivially be changed here. */
constexpr CommandType
parse_command_type(const std::string_view view) noexcept
{
  using namespace std::literals::string_view_literals;
  switch (view.size()) {
  case 4: {
    if (view == "goto"sv) {
      return CommandType::Goto;
    }
    if (view == "next"sv) {
      return CommandType::Next;
    }
  } break;
  case 5: {
    if (view == "pause"sv) {
      return CommandType::Pause;
    }
  } break;
  case 6: {
    if (view == "attach"sv) {
      return CommandType::Attach;
    }
    if (view == "launch"sv) {
      return CommandType::Launch;
    }
    if (view == "scopes"sv) {
      return CommandType::Scopes;
    }
    if (view == "source"sv) {
      return CommandType::Source;
    }
    if (view == "stepIn"sv) {
      return CommandType::StepIn;
    }
  } break;
  case 7: {
    if (view == "modules"sv) {
      return CommandType::Modules;
    }
    if (view == "restart"sv) {
      return CommandType::Restart;
    }
    if (view == "stepOut"sv) {
      return CommandType::StepOut;
    }
    if (view == "threads"sv) {
      return CommandType::Threads;
    }
  } break;
  case 8: {
    if (view == "continue"sv) {
      return CommandType::Continue;
    }
    if (view == "evaluate"sv) {
      return CommandType::Evaluate;
    }
    if (view == "stepBack"sv) {
      return CommandType::StepBack;
    }
  } break;
  case 9: {
    if (view == "terminate"sv) {
      return CommandType::Terminate;
    }
    if (view == "variables"sv) {
      return CommandType::Variables;
    }
  } break;
  case 10: {
    if (view == "disconnect"sv) {
      return CommandType::Disconnect;
    }
    if (view == "initialize"sv) {
      return CommandType::Initialize;
    }
    if (view == "readMemory"sv) {
      return CommandType::ReadMemory;
    }
    if (view == "stackTrace"sv) {
      return CommandType::StackTrace;
    }
  } break;
  case 11: {
    if (view == "completions"sv) {
      return CommandType::Completions;
    }
    if (view == "disassemble"sv) {
      return CommandType::Disassemble;
    }
    if (view == "gotoTargets"sv) {
      return CommandType::GotoTargets;
    }
    if (view == "setVariable"sv) {
      return CommandType::SetVariable;
    }
    if (view == "writeMemory"sv) {
      return CommandType::WriteMemory;
    }
  } break;
  case 12: {
    if (view == "restartFrame"sv) {
      return CommandType::RestartFrame;
    }
    if (view == "importScript"sv) {
      return CommandType::ImportScript;
    }
  } break;
  case 13: {
    if (view == "customRequest"sv) {
      return CommandType::CustomRequest;
    }
    if (view == "exceptionInfo"sv) {
      return CommandType::ExceptionInfo;
    }
    if (view == "loadedSources"sv) {
      return CommandType::LoadedSources;
    }
    if (view == "setExpression"sv) {
      return CommandType::SetExpression;
    }
    if (view == "stepInTargets"sv) {
      return CommandType::StepInTargets;
    }
  } break;
  case 14: {
    if (view == "setBreakpoints"sv) {
      return CommandType::SetBreakpoints;
    }
  } break;
  case 15: {
    if (view == "reverseContinue"sv) {
      return CommandType::ReverseContinue;
    }
  } break;
  case 16: {
    if (view == "terminateThreads"sv) {
      return CommandType::TerminateThreads;
    }
  } break;
  case 17: {
    if (view == "configurationDone"sv) {
      return CommandType::ConfigurationDone;
    }
  } break;
  case 18: {
    if (view == "dataBreakpointInfo"sv) {
      return CommandType::DataBreakpointInfo;
    }
    if (view == "setDataBreakpoints"sv) {
      return CommandType::SetDataBreakpoints;
    }
  } break;
  case 19: {
    if (view == "breakpointLocations"sv) {
      return CommandType::BreakpointLocations;
    }
  } break;
  case 22: {
    if (view == "setFunctionBreakpoints"sv) {
      return CommandType::SetFunctionBreakpoints;
    }
  } break;
  case 23: {
    if (view == "setExceptionBreakpoints"sv) {
      return CommandType::SetExceptionBreakpoints;
    }
  } break;
  case 25: {
    if (view == "setInstructionBreakpoints"sv) {
      return CommandType::SetInstructionBreakpoints;
    }
  } break;
  default:
    break;
  }
  return CommandType::UNKNOWN;
}

template <typename K, std::size_t S> struct RequestMap
{
  using enum CommandType;
  std::array<std::pair<K, CommandType>, S> data;
  // clang-format off
  [[nodiscard("Must use return value from this function - otherwise optimizations might not kick in")]]
  // clang-format on
  constexpr CommandType
  get_command(std::string_view key) const noexcept
  {
    const auto itr =
      std::find_if(std::cbegin(data), std::cend(data), [&key](const auto &p) { return p.first == key; });
    [[likely]] if (itr != std::cend(data)) {
      return itr->second;
    } else {
      return CommandType::UNKNOWN;
    }
  }
};
static constexpr std::array<std::pair<std::string_view, CommandType>, std::to_underlying(CommandType::UNKNOWN)>
  str_cmd_conversion_map{{{"attach"sv, CommandType::Attach},
                          {"breakpointLocations"sv, CommandType::BreakpointLocations},
                          {"completions"sv, CommandType::Completions},
                          {"configurationDone"sv, CommandType::ConfigurationDone},
                          {"continue"sv, CommandType::Continue},
                          {"customRequest"sv, CommandType::CustomRequest},
                          {"dataBreakpointInfo"sv, CommandType::DataBreakpointInfo},
                          {"disassemble"sv, CommandType::Disassemble},
                          {"disconnect"sv, CommandType::Disconnect},
                          {"evaluate"sv, CommandType::Evaluate},
                          {"exceptionInfo"sv, CommandType::ExceptionInfo},
                          {"goto"sv, CommandType::Goto},
                          {"gotoTargets"sv, CommandType::GotoTargets},
                          {"initialize"sv, CommandType::Initialize},
                          {"launch"sv, CommandType::Launch},
                          {"loadedSources"sv, CommandType::LoadedSources},
                          {"modules"sv, CommandType::Modules},
                          {"next"sv, CommandType::Next},
                          {"pause"sv, CommandType::Pause},
                          {"readMemory"sv, CommandType::ReadMemory},
                          {"restart"sv, CommandType::Restart},
                          {"restartFrame"sv, CommandType::RestartFrame},
                          {"reverseContinue"sv, CommandType::ReverseContinue},
                          {"scopes"sv, CommandType::Scopes},
                          {"setBreakpoints"sv, CommandType::SetBreakpoints},
                          {"setDataBreakpoints"sv, CommandType::SetDataBreakpoints},
                          {"setExceptionBreakpoints"sv, CommandType::SetExceptionBreakpoints},
                          {"setExpression"sv, CommandType::SetExpression},
                          {"setFunctionBreakpoints"sv, CommandType::SetFunctionBreakpoints},
                          {"setInstructionBreakpoints"sv, CommandType::SetInstructionBreakpoints},
                          {"setVariable"sv, CommandType::SetVariable},
                          {"source"sv, CommandType::Source},
                          {"stackTrace"sv, CommandType::StackTrace},
                          {"stepBack"sv, CommandType::StepBack},
                          {"stepIn"sv, CommandType::StepIn},
                          {"stepInTargets"sv, CommandType::StepInTargets},
                          {"stepOut"sv, CommandType::StepOut},
                          {"terminate"sv, CommandType::Terminate},
                          {"terminateThreads"sv, CommandType::TerminateThreads},
                          {"threads"sv, CommandType::Threads},
                          {"variables"sv, CommandType::Variables},
                          {"writeMemory"sv, CommandType::WriteMemory}}};

// We've parsed the header of a request / message and we've verified that the body
// is contained in the buffer that we read into.
// - `payload_length` is the length of the body
// - `header_begin` points to the first position of the header in the buffer
// - `payload_begin` points to the first byte of the body in the buffer
struct ContentDescriptor
{
  // The parsed payload length from the header
  u64 payload_length;
  // offset to start of the header into the owning buffer
  u64 packet_offset;
  // first byte of header
  const char *header_begin;
  // first byte of payload
  const char *payload_begin;

  std::string_view payload() const noexcept;
};

// We've parsed the header of a request / message, but we haven't read the entire body
// - `payload_length` is the length of the body
// - `payload_missing` is how much of the body that was missing (and needs to be added after the next read)
// - `payload_begin` points to the first byte of the body in the buffer
struct PartialContentDescriptor
{
  u64 payload_length;
  u64 payload_missing;
  const char *payload_begin;
};

// data that we couldn't parse "Content-Length" header from, which probably means
// we only read about half of the header (or something like that). We still need to record it though
// so we know what to copy and construct the header from, on the next read.
// - `length` - the length of the un-parseable data
// - `begin` - points to first byte in sub-range of bytes in the buffer where this Partial was found (it *must* be
// the last item found in the buffer)
struct RemainderData
{
  u64 length;
  u64 offset;
};

using ViewMatchResult = std::match_results<std::string_view::const_iterator>;
using ContentParse = std::variant<ContentDescriptor, PartialContentDescriptor, RemainderData>;

std::vector<ContentParse> parse_headers_from(const std::string_view buffer_view, bool *no_partials = nullptr) noexcept;

void setup_logging(std::fstream &logger);
} // namespace ui::dap