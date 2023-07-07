#include "interface.h"
#include "../../tracer.h"
#include "dap_defs.h"
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <sys/epoll.h>
#include <sys/mman.h>

namespace ui::dap {
using namespace std::string_literals;

// Ordered by size, not alphabetically
// as benchmarks seem to suggest that this gives better performance
// https://quick-bench.com/q/EsrIbPt2A2455D-RON5_2TXxD9I
static constexpr std::string_view strings[]{
    "Goto",
    "Next",
    "Pause",
    "Attach",
    "Launch",
    "Scopes",
    "Source",
    "StepIn",
    "Modules",
    "Restart",
    "StepOut",
    "Threads",
    "Continue",
    "Evaluate",
    "StepBack",
    "Terminate",
    "Variables",
    "Disconnect",
    "Initialize",
    "ReadMemory",
    "StackTrace",
    "Completions",
    "Disassemble",
    "GotoTargets",
    "SetVariable",
    "WriteMemory",
    "RestartFrame",
    "CustomRequest",
    "ExceptionInfo",
    "LoadedSources",
    "SetExpression",
    "StepInTargets",
    "SetBreakpoints",
    "ReverseContinue",
    "TerminateThreads",
    "ConfigurationDone",
    "DataBreakpointInfo",
    "SetDataBreakpoints",
    "BreakpointLocations",
    "SetFunctionBreakpoints",
    "SetExceptionBreakpoints",
    "SetInstructionBreakpoints",
};

using json = nlohmann::json;

DAP::DAP(Tracer *tracer, int input_fd, int output_fd) noexcept
    : tracer{tracer}, input_fd(input_fd), output_fd(output_fd), epoll_fd(epoll_create1(0)), event{},
      keep_running(true)
{
  buffer = (char *)mmap(nullptr, 4096 * 3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
  ASSERT(buffer != MAP_FAILED, "Failed to mmap in read buffer; {}", strerror(errno));
  ASSERT(epoll_fd != 1, "Failed to create epoll fd instance {}", strerror(errno));
  event.events = EPOLLIN;
  event.data.fd = input_fd;

  ASSERT(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, 0, &event) != -1, "Failed to add fd {} to epoll: {}", input_fd,
         strerror(errno));
}

static const std::regex content_length = std::regex{R"(Content-Length: (\d+)\s{4})"};

std::vector<ContentParse>
parse_buffer(const std::string_view buffer_view) noexcept
{
  std::vector<ContentParse> result;

  std::smatch m;
  std::string_view internal_view{buffer_view};
  ViewMatchResult base_match;
  while (std::regex_search(internal_view.begin(), internal_view.end(), base_match, content_length)) {
    if (base_match.size() == 2) {
      std::sub_match<std::string_view::const_iterator> base_sub_match = base_match[1];
      std::string_view len_str{base_sub_match.first, base_sub_match.second};
      u64 len;
      const auto res = std::from_chars(len_str.data(), len_str.data() + len_str.size(), len);
      if (res.ec != std::errc()) {
        PANIC(fmt::format("Hard failure if <regex> thinks it's found a number when it didn't"));
      }
      ASSERT(res.ec != std::errc(), "Failed to parse Content Length {}", len_str);
      if (base_match.position() + base_match.length() + len <= internal_view.size()) {
        result.push_back(ContentDescriptor{.payload_length = len,
                                           .header_begin = internal_view.data() + base_match.position(),
                                           .payload_begin = internal_view.data() + base_match.length()});
        internal_view.remove_prefix(base_match.position() + base_match.length() + len);
      } else {
        result.push_back(PartialContentDescriptor{
            .payload_length = len,
            .payload_missing = (base_match.position() + base_match.length() + len) - internal_view.size(),
            .payload_begin = internal_view.data() + base_match.position() + base_match.length()});
        internal_view.remove_prefix(internal_view.size());
      }
    }
  }
  if (!internal_view.empty()) {
    result.push_back(RemainderData{.length = internal_view.size(), .begin = internal_view.data()});
  }
  return result;
}

void
DAP::infinite_poll() noexcept
{
  epoll_event events[5];

  while (keep_running) {
    const auto event_count = epoll_wait(epoll_fd, events, 5, 30000);
    char *free_ptr = buffer;
    char *curr_ptr = buffer;
    for (auto i = 0; i < event_count; i++) {
      const auto bytes_read = read(events[i].data.fd, curr_ptr, 4096 * 3);
      if (bytes_read <= 4096 * 3) {
        free_ptr = buffer + bytes_read;
      }
      const auto request_headers = parse_buffer({buffer, free_ptr});
    }
  }
}

Command
DAP::parse_command_type(std::string_view str) noexcept
{
  return parse_input(str);
}

/* I've actually benchmarked this, and this is faster than a naive constexpr-map *and* a std::unordered_map
 * lookup by a *LARGE* margin. As such I see no good reason at all to change this as the DA-protocol is well
 * defined when it comes to it's commands. Any change to the spec will trivially be changed here. */
constexpr Command
parse_input(const std::string_view view) noexcept
{
  using namespace std::literals::string_view_literals;
  switch (view.size()) {
  case 4: {
    if (view == "Goto"sv)
      return Command::Goto;
    if (view == "Next"sv)
      return Command::Next;
  } break;
  case 5: {
    if (view == "Pause"sv)
      return Command::Pause;
  } break;
  case 6: {
    if (view == "Attach"sv)
      return Command::Attach;
    if (view == "Launch"sv)
      return Command::Launch;
    if (view == "Scopes"sv)
      return Command::Scopes;
    if (view == "Source"sv)
      return Command::Source;
    if (view == "StepIn"sv)
      return Command::StepIn;
  } break;
  case 7: {
    if (view == "Modules"sv)
      return Command::Modules;
    if (view == "Restart"sv)
      return Command::Restart;
    if (view == "StepOut"sv)
      return Command::StepOut;
    if (view == "Threads"sv)
      return Command::Threads;
  } break;
  case 8: {
    if (view == "Continue"sv)
      return Command::Continue;
    if (view == "Evaluate"sv)
      return Command::Evaluate;
    if (view == "StepBack"sv)
      return Command::StepBack;
  } break;
  case 9: {
    if (view == "Terminate"sv)
      return Command::Terminate;
    if (view == "Variables"sv)
      return Command::Variables;
  } break;
  case 10: {
    if (view == "Disconnect"sv)
      return Command::Disconnect;
    if (view == "Initialize"sv)
      return Command::Initialize;
    if (view == "ReadMemory"sv)
      return Command::ReadMemory;
    if (view == "StackTrace"sv)
      return Command::StackTrace;
  } break;
  case 11: {
    if (view == "Completions"sv)
      return Command::Completions;
    if (view == "Disassemble"sv)
      return Command::Disassemble;
    if (view == "GotoTargets"sv)
      return Command::GotoTargets;
    if (view == "SetVariable"sv)
      return Command::SetVariable;
    if (view == "WriteMemory"sv)
      return Command::WriteMemory;
  } break;
  case 12: {
    if (view == "RestartFrame"sv)
      return Command::RestartFrame;
  } break;
  case 13: {
    if (view == "CustomRequest"sv)
      return Command::CustomRequest;
    if (view == "ExceptionInfo"sv)
      return Command::ExceptionInfo;
    if (view == "LoadedSources"sv)
      return Command::LoadedSources;
    if (view == "SetExpression"sv)
      return Command::SetExpression;
    if (view == "StepInTargets"sv)
      return Command::StepInTargets;
  } break;
  case 14: {
    if (view == "SetBreakpoints"sv)
      return Command::SetBreakpoints;
  } break;
  case 15: {
    if (view == "ReverseContinue"sv)
      return Command::ReverseContinue;
  } break;
  case 16: {
    if (view == "TerminateThreads"sv)
      return Command::TerminateThreads;
  } break;
  case 17: {
    if (view == "ConfigurationDone"sv)
      return Command::ConfigurationDone;
  } break;
  case 18: {
    if (view == "DataBreakpointInfo"sv)
      return Command::DataBreakpointInfo;
    if (view == "SetDataBreakpoints"sv)
      return Command::SetDataBreakpoints;
  } break;
  case 19: {
    if (view == "BreakpointLocations"sv)
      return Command::BreakpointLocations;
  } break;
  case 22: {
    if (view == "SetFunctionBreakpoints"sv)
      return Command::SetFunctionBreakpoints;
  } break;
  case 23: {
    if (view == "SetExceptionBreakpoints"sv)
      return Command::SetExceptionBreakpoints;
  } break;
  case 25: {
    if (view == "SetInstructionBreakpoints"sv)
      return Command::SetInstructionBreakpoints;
  } break;
  default:
    break;
  }
  return Command::UNKNOWN;
}

} // namespace ui::dap