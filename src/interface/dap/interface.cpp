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

std::string_view
ContentDescriptor::payload() const noexcept
{
  return std::string_view{payload_begin, payload_begin + payload_length};
}

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
    : tracer{tracer}, input_fd(input_fd), output_fd(output_fd), event{}, keep_running(true)
{
  epoll_fd = epoll_create1(0);
  ASSERT(epoll_fd != 1, "Failed to create epoll fd instance {}", strerror(errno));
  buffer = mmap_buffer<char>(4096 * 3);
  event.events = EPOLLIN;
  event.data.fd = input_fd;

  ASSERT(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, 0, &event) != -1, "Failed to add fd {} to epoll: {}", input_fd,
         strerror(errno));
}

static const std::regex content_length = std::regex{R"(Content-Length: (\d+)\s{4})"};

std::vector<ContentParse>
parse_buffer(const std::string_view buffer_view, bool *all_msgs_ok) noexcept
{
  std::vector<ContentParse> result;

  std::smatch m;
  std::string_view internal_view{buffer_view};
  ViewMatchResult base_match;
  bool partial_found = false;
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
        partial_found = true;
      }
    }
  }
  if (!internal_view.empty()) {
    result.push_back(RemainderData{.length = internal_view.size(), .begin = internal_view.data()});
    partial_found = true;
  }
  if (all_msgs_ok != nullptr)
    *all_msgs_ok = !partial_found;
  return result;
}

void
DAP::input_wait_loop() noexcept
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
      bool no_partials = false;
      const auto request_headers = parse_buffer({buffer, free_ptr}, &no_partials);
      if (no_partials) {
        for (auto &&hdr : request_headers) {
          auto cd = maybe_unwrap<ContentDescriptor>(hdr);
          const auto packet = cd->payload();
          auto obj = json::parse(packet);
          std::string_view cmd;
          obj["command"].get_to(cmd);
          auto command = parse_input(cmd);
        }

/* This is technically much safer - so why not during release builds?
 * My justification is this; by having 2 distinct logic paths, if an error occurs
 * it's easy to see if it works in debug or not; constraining the domain size of where the issues may be.
 * We don't want to do unnecessary writes when we don't have to.  */
#ifdef MDB_DEBUG
        std::memset(buffer, 0, std::distance(buffer, free_ptr));
#endif
        // since there's no partials left in the buffer, we reset it
        free_ptr = buffer;
        curr_ptr = buffer;
      } else {
      }
    }
  }
}

} // namespace ui::dap