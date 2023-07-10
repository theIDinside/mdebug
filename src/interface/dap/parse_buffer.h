#pragma once
#include "../../common.h"
#include "dap_defs.h"
#include <regex>
#include <utility>

namespace ui::dap {
using namespace std::string_view_literals;
/* I've actually benchmarked this, and this is faster than a naive constexpr-map *and* a std::unordered_map
 * lookup by a *LARGE* margin. As such I see no good reason at all to change this as the DA-protocol is well
 * defined when it comes to it's commands. Any change to the spec will trivially be changed here. */
constexpr Command
parse_command_type(const std::string_view view) noexcept
{
  using namespace std::literals::string_view_literals;
  switch (view.size()) {
  case 4: {
    if (view == "goto"sv)
      return Command::Goto;
    if (view == "next"sv)
      return Command::Next;
  } break;
  case 5: {
    if (view == "pause"sv)
      return Command::Pause;
  } break;
  case 6: {
    if (view == "attach"sv)
      return Command::Attach;
    if (view == "launch"sv)
      return Command::Launch;
    if (view == "scopes"sv)
      return Command::Scopes;
    if (view == "source"sv)
      return Command::Source;
    if (view == "stepIn"sv)
      return Command::StepIn;
  } break;
  case 7: {
    if (view == "modules"sv)
      return Command::Modules;
    if (view == "restart"sv)
      return Command::Restart;
    if (view == "stepOut"sv)
      return Command::StepOut;
    if (view == "threads"sv)
      return Command::Threads;
  } break;
  case 8: {
    if (view == "continue"sv)
      return Command::Continue;
    if (view == "evaluate"sv)
      return Command::Evaluate;
    if (view == "stepBack"sv)
      return Command::StepBack;
  } break;
  case 9: {
    if (view == "terminate"sv)
      return Command::Terminate;
    if (view == "variables"sv)
      return Command::Variables;
  } break;
  case 10: {
    if (view == "disconnect"sv)
      return Command::Disconnect;
    if (view == "initialize"sv)
      return Command::Initialize;
    if (view == "readMemory"sv)
      return Command::ReadMemory;
    if (view == "stackTrace"sv)
      return Command::StackTrace;
  } break;
  case 11: {
    if (view == "completions"sv)
      return Command::Completions;
    if (view == "disassemble"sv)
      return Command::Disassemble;
    if (view == "gotoTargets"sv)
      return Command::GotoTargets;
    if (view == "setVariable"sv)
      return Command::SetVariable;
    if (view == "writeMemory"sv)
      return Command::WriteMemory;
  } break;
  case 12: {
    if (view == "restartFrame"sv)
      return Command::RestartFrame;
  } break;
  case 13: {
    if (view == "customRequest"sv)
      return Command::CustomRequest;
    if (view == "exceptionInfo"sv)
      return Command::ExceptionInfo;
    if (view == "loadedSources"sv)
      return Command::LoadedSources;
    if (view == "setExpression"sv)
      return Command::SetExpression;
    if (view == "stepInTargets"sv)
      return Command::StepInTargets;
  } break;
  case 14: {
    if (view == "setBreakpoints"sv)
      return Command::SetBreakpoints;
  } break;
  case 15: {
    if (view == "reverseContinue"sv)
      return Command::ReverseContinue;
  } break;
  case 16: {
    if (view == "terminateThreads"sv)
      return Command::TerminateThreads;
  } break;
  case 17: {
    if (view == "configurationDone"sv)
      return Command::ConfigurationDone;
  } break;
  case 18: {
    if (view == "dataBreakpointInfo"sv)
      return Command::DataBreakpointInfo;
    if (view == "setDataBreakpoints"sv)
      return Command::SetDataBreakpoints;
  } break;
  case 19: {
    if (view == "breakpointLocations"sv)
      return Command::BreakpointLocations;
  } break;
  case 22: {
    if (view == "setFunctionBreakpoints"sv)
      return Command::SetFunctionBreakpoints;
  } break;
  case 23: {
    if (view == "setExceptionBreakpoints"sv)
      return Command::SetExceptionBreakpoints;
  } break;
  case 25: {
    if (view == "setInstructionBreakpoints"sv)
      return Command::SetInstructionBreakpoints;
  } break;
  default:
    break;
  }
  return Command::UNKNOWN;
}

template <typename K, std::size_t S> struct RequestMap
{
  using enum Command;
  std::array<std::pair<K, Command>, S> data;
  // clang-format off
  [[nodiscard("Must use return value from this function - otherwise optimizations might not kick in")]]
  // clang-format on
  constexpr Command
  get_command(std::string_view key) const noexcept
  {
    const auto itr =
        std::find_if(std::cbegin(data), std::cend(data), [&key](const auto &p) { return p.first == key; });
    [[likely]] if (itr != std::cend(data)) {
      return itr->second;
    } else {
      return Command::UNKNOWN;
    }
  }
};
using enum Command;
static constexpr std::array<std::pair<std::string_view, Command>, std::to_underlying(Command::UNKNOWN)>
    str_cmd_conversion_map{{{"attach"sv, Attach},
                            {"breakpointLocations"sv, BreakpointLocations},
                            {"completions"sv, Completions},
                            {"configurationDone"sv, ConfigurationDone},
                            {"continue"sv, Continue},
                            {"customRequest"sv, CustomRequest},
                            {"dataBreakpointInfo"sv, DataBreakpointInfo},
                            {"disassemble"sv, Disassemble},
                            {"disconnect"sv, Disconnect},
                            {"evaluate"sv, Evaluate},
                            {"exceptionInfo"sv, ExceptionInfo},
                            {"goto"sv, Goto},
                            {"gotoTargets"sv, GotoTargets},
                            {"initialize"sv, Initialize},
                            {"launch"sv, Launch},
                            {"loadedSources"sv, LoadedSources},
                            {"modules"sv, Modules},
                            {"next"sv, Next},
                            {"pause"sv, Pause},
                            {"readMemory"sv, ReadMemory},
                            {"restart"sv, Restart},
                            {"restartFrame"sv, RestartFrame},
                            {"reverseContinue"sv, ReverseContinue},
                            {"scopes"sv, Scopes},
                            {"setBreakpoints"sv, SetBreakpoints},
                            {"setDataBreakpoints"sv, SetDataBreakpoints},
                            {"setExceptionBreakpoints"sv, SetExceptionBreakpoints},
                            {"setExpression"sv, SetExpression},
                            {"setFunctionBreakpoints"sv, SetFunctionBreakpoints},
                            {"setInstructionBreakpoints"sv, SetInstructionBreakpoints},
                            {"setVariable"sv, SetVariable},
                            {"source"sv, Source},
                            {"stackTrace"sv, StackTrace},
                            {"stepBack"sv, StepBack},
                            {"stepIn"sv, StepIn},
                            {"stepInTargets"sv, StepInTargets},
                            {"stepOut"sv, StepOut},
                            {"terminate"sv, Terminate},
                            {"terminateThreads"sv, TerminateThreads},
                            {"threads"sv, Threads},
                            {"variables"sv, Variables},
                            {"writeMemory"sv, WriteMemory}}};

// We've parsed the header of a request / message and we've verified that the body
// is contained in the buffer that we read into.
// - `payload_length` is the length of the body
// - `header_begin` points to the first position of the header in the buffer
// - `payload_begin` points to the first byte of the body in the buffer
struct ContentDescriptor
{
  u64 payload_length;
  const char *header_begin;
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
  const char *begin;
};

using ViewMatchResult = std::match_results<std::string_view::const_iterator>;
using ContentParse = std::variant<ContentDescriptor, PartialContentDescriptor, RemainderData>;

std::vector<ContentParse> parse_buffer(const std::string_view buffer_view, bool *no_partials = nullptr) noexcept;
} // namespace ui::dap