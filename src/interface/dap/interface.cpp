#include "interface.h"
#include "../../tracer.h"
#include "commands.h"
#include "events.h"
#include "fmt/core.h"
#include "parse_buffer.h"
#include <algorithm>
#include <charconv>
#include <chrono>
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
      keep_running(true), output_message_lock{}, events_queue{}, seq(0)
{
  post_event_fd = Pipe::non_blocking_read();
  buffer = mmap_buffer<char>(4096 * 3);
  tracee_stdout_buffer = mmap_buffer<char>(4096 * 3);
  auto flags = fcntl(master_pty_fd, F_GETFL);
  VERIFY(flags != -1, "Failed to get pty flags");
  VERIFY(fcntl(master_pty_fd, F_SETFL, flags | FNDELAY | FNONBLOCK) != -1, "Failed to set FNDELAY on pty");
}

Event *
DAP::pop_event() noexcept
{
  VERIFY(!events_queue.empty(), "Can't pop events from an empty list!");
  LockGuard<SpinLock> lock{output_message_lock};
  Event *evt = events_queue.front();
  std::uintptr_t test = (std::uintptr_t)evt;
  events_queue.pop_front();
  ASSERT((std::uintptr_t)evt == test, "pointer changed value under our feet");
  return evt;
}

void
DAP::write_protocol_message(const SerializedProtocolMessage &msg) noexcept
{
  VERIFY(write(tracer_out_fd, msg.header.data(), msg.header.size()) != -1, "Failed to write '{}'", msg.header);
  VERIFY(write(tracer_out_fd, msg.payload.data(), msg.payload.size()) != -1, "Failed to write '{}'", msg.payload);
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
          while (!events_queue.empty()) {
            auto evt = pop_event();
            const auto protocol_msg = evt->serialize(seq++);
            write_protocol_message(protocol_msg);
            delete evt;
          }
        } else if (pfds[i].fd == master_pty_fd && (pfds[i].revents & POLLIN)) {
          auto bytes_read = read(master_pty_fd, tracee_stdout_buffer, 4096 * 3);
          if (bytes_read == -1)
            continue;
          std::string_view data{tracee_stdout_buffer, static_cast<u64>(bytes_read)};
          // we do this _simply_ to escape the string (and utf-8 it?)
          json str = data;
          const auto escaped_body_contents = str.dump();
          const auto payload = fmt::format(
              R"({{"seq": {},"type":"event","event":"output","body":{{ "category": "stdout", "output": {}}}}})",
              seq++, escaped_body_contents);
          const auto header = fmt::format("Content-Length: {}\r\n\r\n\n", payload.size());
          VERIFY(write(tracer_out_fd, header.data(), header.size()) != -1, "Failed to write '{}'", header);
          VERIFY(write(tracer_out_fd, payload.data(), payload.size()) != -1, "Failed to write '{}'", payload);
        }
      }
    }
    if (!keep_running)
      cleanup_times--;
  }
  cleaned_up = true;
}

void
DAP::post_event(Event *serializable_event) noexcept
{
  {
    LockGuard<SpinLock> guard{output_message_lock};
    events_queue.push_back(serializable_event);
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
DAP::clean_up() noexcept
{
  using namespace std::chrono_literals;
  keep_running = false;
}

} // namespace ui::dap