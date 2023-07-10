#include "interface.h"
#include "../../tracer.h"
#include "commands.h"
#include "parse_buffer.h"
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <ranges>
#include <string>
#include <string_view>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <thread>
namespace ui::dap {
using namespace std::string_literals;

static constexpr auto GO = "+"sv;
std::string_view
ContentDescriptor::payload() const noexcept
{
  return std::string_view{payload_begin, payload_begin + payload_length};
}
/*
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
*/

using json = nlohmann::json;

DAP::DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd, int master_pty_fd) noexcept
    : tracer{tracer}, tracer_in_fd(tracer_input_fd), tracer_out_fd(tracer_output_fd), master_pty_fd(master_pty_fd),
      keep_running(true), output_message_lock{}, msg{}, seq(0)
{
  post_event_fd = Pipe::non_blocking_read();
  buffer = mmap_buffer<char>(4096 * 3);
  tracee_stdout_buffer = mmap_buffer<char>(4096 * 3);
  auto flags = fcntl(master_pty_fd, F_GETFL);
  VERIFY(flags != -1, "Failed to get pty flags");
  VERIFY(fcntl(master_pty_fd, F_SETFL, flags | FNDELAY | FNONBLOCK) != -1, "Failed to set FNDELAY on pty");
}

std::unique_ptr<std::string>
DAP::pop_message() noexcept
{
  VERIFY(!messages.empty(), "Message queue must be non-empty");
  LockGuard<SpinLock> lock{output_message_lock};
  auto msg = std::move(messages.front());
  messages.pop_front();
  return msg;
}

void
DAP::run_ui_loop() noexcept
{
  auto cleanup_times = 5;
  while (keep_running || cleanup_times > 0) {
    epoll_event events[5];
    struct pollfd pfds[3]{
        cfg_read_poll(tracer_in_fd, 0),
        cfg_read_poll(post_event_fd.read_end(), 0),
        cfg_read_poll(master_pty_fd, 0),
    };

    auto ready = poll(pfds, 3, 100);
    VERIFY(ready != -1, "Failed to poll");
    char *free_ptr = buffer;
    char *curr_ptr = buffer;

    for (auto i = 0; i < 3 && ready > 0; i++) {
      if ((pfds[i].revents & POLLIN) || ((pfds[i].revents & POLLOUT))) {
        if (pfds[i].fd == tracer_in_fd) {
          // process commands
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
              std::string_view cmd_name;
              obj["command"].get_to(cmd_name);
              auto cmd = parse_command(parse_command_type(cmd_name), obj["arguments"]);
              tracer->accept_command(cmd);
            }
            // since there's no partials left in the buffer, we reset it
            free_ptr = buffer;
            curr_ptr = buffer;
          }
        } else if (pfds[i].fd == post_event_fd.read_end()) {
          // process new messages (strings) posted on the output queue
          char buf[GO.size()];
          read(post_event_fd.read_end(), buf, GO.size());
          while (!messages.empty()) {
            const auto msg = pop_message();
            json j;
            j["seq"] = seq++;
            j["type"] = "event";
            j["event"] = "output";
            j["body"] = {};
            j["body"]["category"] = "console";
            j["body"]["output"] = fmt::format("{}", *msg);
            const auto dap_payload = j.dump();
            const auto hdr_with_paylod =
                fmt::format("Content-Length: {}\r\n\r\n{}", dap_payload.size(), dap_payload);
            VERIFY(write(tracer_out_fd, hdr_with_paylod.data(), hdr_with_paylod.size()) != -1,
                   "Failed to write '{}'", hdr_with_paylod);
          }
          while (!msg.empty()) {
            handle_first_json([&seq = this->seq, fd = tracer_out_fd](json &j) {
              j["seq"] = seq++;
              const auto dap_payload = j.dump();
              const auto hdr_with_paylod =
                  fmt::format("Content-Length: {}\r\n\r\n{}", dap_payload.size(), dap_payload);
              VERIFY(write(fd, hdr_with_paylod.data(), hdr_with_paylod.size()) != -1, "Failed to write '{}'",
                     hdr_with_paylod);
            });
          }
        } else if (pfds[i].fd == master_pty_fd && (pfds[i].revents & POLLIN)) {
          auto bytes_read = read(master_pty_fd, tracee_stdout_buffer, 4096 * 3);
          if (bytes_read == -1)
            continue;

          std::string_view data{tracee_stdout_buffer, static_cast<u64>(bytes_read)};
          json j;
          j["seq"] = seq++;
          j["type"] = "event";
          j["event"] = "output";
          j["body"] = {};
          j["body"]["category"] = "stdout";
          j["body"]["output"] = fmt::format("{}", data);
          const auto dap_payload = j.dump();

          const auto hdr_with_paylod =
              fmt::format("Content-Length: {}\r\n\r\n{}\n", dap_payload.size(), dap_payload);
          VERIFY(write(tracer_out_fd, hdr_with_paylod.data(), hdr_with_paylod.size()) != -1,
                 "Failed to write '{}'", hdr_with_paylod);
        }
      }
    }
    if (!keep_running)
      cleanup_times--;
  }
}

// Post `output_message` to the DAP output message queue
void
DAP::post_output_event(std::unique_ptr<std::string> output_message) noexcept
{
  {
    LockGuard<SpinLock> guard{output_message_lock};
    messages.push_back(std::move(output_message));
  }
  notify_new_message();
}

void
DAP::post_json_event(json &&dictionary) noexcept
{
  {
    LockGuard<SpinLock> guard{output_message_lock};
    msg.push_back(std::move(dictionary));
  }
  notify_new_message();
}

int
DAP::get_post_event_fd() noexcept
{
  return post_event_fd.write_end();
}

void
DAP::notify_new_message() noexcept
{
  ASSERT(write(post_event_fd.write_end(), GO.data(), GO.size()) != -1,
         "failed to notify DAP interface of new message");
}

void
DAP::kill_ui() noexcept
{
  keep_running = false;
}

} // namespace ui::dap