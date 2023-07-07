#pragma once

#include "../../common.h"
#include "dap_defs.h"
#include <algorithm>
#include <array>
#include <regex>
#include <string_view>
#include <sys/epoll.h>
#include <utility>
#include <variant>
#include <vector>

class Tracer;
/* The different DAP commands/requests */

namespace ui::dap {
using namespace std::string_view_literals;

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

struct Request
{
  Command command;
  std::vector<std::string> arguments;
};

class DAP
{
public:
  explicit DAP(Tracer *tracer, int input_fd, int output_fd) noexcept;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.
  void infinite_poll() noexcept;
  Command parse_command_type(std::string_view str) noexcept;

private:
  Tracer *tracer;
  int input_fd;
  int output_fd;
  int epoll_fd;
  epoll_event event;
  bool keep_running;
  char *buffer;
};

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

std::vector<ContentParse> parse_buffer(const std::string_view buffer_view) noexcept;
constexpr Command parse_input(const std::string_view) noexcept;
}; // namespace ui::dap