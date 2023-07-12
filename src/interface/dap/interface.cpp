#include "interface.h"
#include "../../tracer.h"
#include "commands.h"
#include "fmt/core.h"
#include "parse_buffer.h"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <ostream>
#include <poll.h>
#include <ranges>
#include <string>
#include <string_view>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <thread>
namespace ui::dap {
using namespace std::string_literals;

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

DAP::DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd, int master_pty_fd,
         utils::Notifier::WriteEnd command_notifier) noexcept
    : tracer{tracer}, tracer_in_fd(tracer_input_fd), tracer_out_fd(tracer_output_fd), master_pty_fd(master_pty_fd),
      keep_running(true), output_message_lock{}, events_queue{}, seq(0), command_notifier(command_notifier)
{
  auto [r, w] = utils::Notifier::notify_pipe();
  posted_event_notifier = w;
  posted_evt_listener = r;
  buffer = mmap_buffer<char>(4096);
  tracee_stdout_buffer = mmap_buffer<char>(4096 * 3);
  auto flags = fcntl(master_pty_fd, F_GETFL);
  VERIFY(flags != -1, "Failed to get pty flags");
  VERIFY(fcntl(master_pty_fd, F_SETFL, flags | FNDELAY | FNONBLOCK) != -1, "Failed to set FNDELAY on pty");
  log_file = std::fstream{"/home/cx/dev/foss/cx/dbm/build-debug/bin/dap.log",
                          std::ios_base::in | std::ios_base::out | std::ios_base::trunc};
  if (!log_file.is_open())
    log_file.open("/home/cx/dev/foss/cx/dbm/build-debug/bin/dap.log",
                  std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
  setup_logging(log_file);
}

UIResultPtr
DAP::pop_event() noexcept
{
  VERIFY(!events_queue.empty(), "Can't pop events from an empty list!");
  LockGuard<SpinLock> lock{output_message_lock};
  UIResultPtr evt = events_queue.front();
  std::uintptr_t test = (std::uintptr_t)evt;
  events_queue.pop_front();
  ASSERT((std::uintptr_t)evt == test, "pointer changed value under our feet");
  return evt;
}

void
DAP::write_protocol_message(std::string_view msg) noexcept
{
  const auto header = fmt::format("Content-Length: {}\r\n\r\n\n", msg.size());
  VERIFY(write(tracer_out_fd, header.data(), header.size()) != -1, "Failed to write '{}'", header);
  VERIFY(write(tracer_out_fd, msg.data(), msg.size()) != -1, "Failed to write '{}'", msg);
}

u64
DAP::new_result_id() noexcept
{
  return seq++;
}

void
DAP::run_ui_loop()
{
  auto cleanup_times = 5;
  ParseBuffer parse_swapbuffer{PAGE_SIZE};

  while (keep_running || cleanup_times > 0) {
    epoll_event events[5];
    struct pollfd pfds[3]{
        cfg_read_poll(tracer_in_fd, 0),
        cfg_read_poll(posted_evt_listener, 0),
        cfg_read_poll(master_pty_fd, 0),
    };

    auto ready = poll(pfds, 3, 100);
    VERIFY(ready != -1, "Failed to poll");

    for (auto i = 0; i < 3 && ready > 0; i++) {
      if ((pfds[i].revents & POLLIN) || ((pfds[i].revents & POLLOUT))) {
        // DAP Requests (or parts of) have came in via stdout
        if (pfds[i].fd == tracer_in_fd) {
          parse_swapbuffer.read_from_fd(events[i].data.fd);
          bool no_partials = false;
          std::string_view buffer_view = parse_swapbuffer.take_view();
          const auto request_headers = parse_headers_from(buffer_view, &no_partials);
          if (no_partials && request_headers.size() > 0) {
            for (auto &&hdr : request_headers) {
              auto cd = maybe_unwrap<ContentDescriptor>(hdr);
              const auto packet = std::string{cd->payload()};
              auto obj = json::parse(packet, nullptr, false);
              std::string_view cmd_name;
              obj["command"].get_to(cmd_name);
              ASSERT(obj.contains("arguments"), "Request did not contain an 'arguments' field: {}", packet);
              auto cmd = parse_command(parse_command_type(cmd_name), std::move(obj["arguments"]));
              tracer->accept_command(cmd);
            }
            command_notifier.notify();
            // since there's no partials left in the buffer, we reset it
            parse_swapbuffer.clear();
          } else {
            if (request_headers.size() > 1) {
              bool parsed_commands = false;
              for (auto i = 0ull; i < request_headers.size() - 1; i++) {
                auto cd = maybe_unwrap<ContentDescriptor>(request_headers[i]);
                const auto packet = std::string{cd->payload()};
                auto obj = json::parse(packet, nullptr, false);
                std::string_view cmd_name;
                obj["command"].get_to(cmd_name);
                ASSERT(obj.contains("arguments"), "Request did not contain an 'arguments' field: {}", packet);
                auto cmd = parse_command(parse_command_type(cmd_name), std::move(obj["arguments"]));
                tracer->accept_command(cmd);
                parsed_commands = true;
              }
              if (parsed_commands) {
                command_notifier.notify();
              }
              auto rd = maybe_unwrap<RemainderData>(request_headers.back());
              parse_swapbuffer.swap(rd->offset);
              ASSERT(parse_swapbuffer.current_size() == rd->length,
                     "Parse Swap Buffer operation failed; expected length {} but got {}", rd->length,
                     parse_swapbuffer.current_size());
            }
          }
        } else if (pfds[i].fd == posted_evt_listener.fd) {
          // process new messages (strings) posted on the output queue
          posted_evt_listener.consume_expected();
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
DAP::post_event(UIResultPtr serializable_event) noexcept
{
  {
    LockGuard<SpinLock> guard{output_message_lock};
    events_queue.push_back(serializable_event);
  }
  notify_new_message();
}

void
DAP::notify_new_message() noexcept
{
  const auto succeeded = posted_event_notifier.notify();
  ASSERT(succeeded, "failed to notify DAP interface of new message due to {}", strerror(errno));
}

void
DAP::clean_up() noexcept
{
  using namespace std::chrono_literals;
  keep_running = false;
}

// Fulfill the `UI` concept in ui_result.h
void
DAP::display_result(std::string_view str) const noexcept
{
  VERIFY(write(tracer_out_fd, str.data(), str.size()) != -1, "Failed to write '{}'", str);
}

} // namespace ui::dap