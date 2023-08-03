#include "interface.h"
#include "../../tracer.h"
#include "../../utils/logger.h"
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
#include <memory_resource>
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

DAP::DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd,
         utils::Notifier::WriteEnd command_notifier) noexcept
    : tracer{tracer}, tracer_in_fd(tracer_input_fd), tracer_out_fd(tracer_output_fd),
      keep_running(true), output_message_lock{}, events_queue{}, seq(0), command_notifier(command_notifier)
{
  auto [r, w] = utils::Notifier::notify_pipe();
  posted_event_notifier = w;
  posted_evt_listener = r;
  buffer = mmap_buffer<char>(4096);
  tracee_stdout_buffer = mmap_buffer<char>(4096 * 3);
}

UIResultPtr
DAP::pop_event() noexcept
{
  VERIFY(!events_queue.empty(), "Can't pop events from an empty list!");
  LockGuard<SpinLock> lock{output_message_lock};
  UIResultPtr evt = events_queue.front();
  events_queue.pop_front();
  return evt;
}

void
DAP::write_protocol_message(std::string_view msg) noexcept
{
  const auto header = fmt::format("Content-Length: {}\r\n\r\n", msg.size());
#ifdef MDB_DEBUG
  logging::Logger::get_logger()->log("dap", fmt::format("WRITING -->{}{}<---", header, msg));
#endif
  VERIFY(write(tracer_out_fd, header.data(), header.size()) != -1, "Failed to write '{}'", header);
  VERIFY(write(tracer_out_fd, msg.data(), msg.size()) != -1, "Failed to write '{}'", msg);
}

void
DAP::run_ui_loop()
{
  auto cleanup_times = 5;
  ParseBuffer parse_swapbuffer{MDB_PAGE_SIZE * 4};
  static constexpr auto DESCRIPTOR_STORAGE_SIZE = MDB_PAGE_SIZE;

  // These are stack data. So when we process events, we don't want to be
  // returning `new`ed memory over and over. Just fill it in our local buffer
  // and we are done with it at each iteration, reusing the same buffer over and over.
  std::byte descriptor_buffer[sizeof(ContentDescriptor) * 15];
  std::byte pmr_buffer[sizeof(pollfd) * 10];

  while (keep_running || cleanup_times > 0) {
    const auto master_pty = current_tty();
    std::pmr::monotonic_buffer_resource descriptor_resource{&descriptor_buffer, DESCRIPTOR_STORAGE_SIZE};
    std::pmr::monotonic_buffer_resource resource{&pmr_buffer, sizeof(pmr_buffer)};
    std::pmr::vector<pollfd> pfds{&resource};
    if (master_pty) {
      pfds.push_back(cfg_read_poll(tracer_in_fd, 0));
      pfds.push_back(cfg_read_poll(posted_evt_listener, 0));
      pfds.push_back(cfg_read_poll(*master_pty, 0));
    } else {
      pfds.push_back(cfg_read_poll(tracer_in_fd, 0));
      pfds.push_back(cfg_read_poll(posted_evt_listener, 0));
    }

    auto ready = poll(pfds.data(), pfds.size(), 1000);
    VERIFY(ready != -1, "Failed to poll");
    for (auto i = 0u; i < pfds.size() && ready > 0; i++) {

      if ((pfds[i].revents & POLLIN) || ((pfds[i].revents & POLLOUT))) {
        // DAP Requests (or parts of) have came in via stdout
        if (pfds[i].fd == tracer_in_fd) {
          parse_swapbuffer.expect_read_from_fd(pfds[i].fd);
          bool no_partials = false;
          const auto request_headers =
              parse_headers_from(parse_swapbuffer.take_view(), descriptor_resource, &no_partials);
          if (no_partials && request_headers.size() > 0) {
            for (auto &&hdr : request_headers) {
              const auto cd = maybe_unwrap<ContentDescriptor>(hdr);
              const auto cmd = parse_command(std::string{cd->payload()});
              tracer->accept_command(cmd);
            }
            command_notifier.notify();
            // since there's no partials left in the buffer, we reset it
            parse_swapbuffer.clear();
          } else {
            if (request_headers.size() > 1) {
              bool parsed_commands = false;
              for (auto i = 0ull; i < request_headers.size() - 1; i++) {
                const auto cd = maybe_unwrap<ContentDescriptor>(request_headers[i]);
                const auto cmd = parse_command(std::string{cd->payload()});
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
        } else if (pfds[i].fd == master_pty && (pfds[i].revents & POLLIN)) {
          const auto bytes_read = read(*master_pty, tracee_stdout_buffer, 4096 * 3);
          if (bytes_read == -1)
            continue;
          std::string_view data{tracee_stdout_buffer, static_cast<u64>(bytes_read)};
          // we do this _simply_ to escape the string (and utf-8 it?)
          json str = data;
          const auto payload = fmt::format(
              R"({{"seq": {},"type":"event","event":"output","body":{{ "category": "stdout", "output": {}}}}})",
              seq++, str.dump());
          const auto header = fmt::format("Content-Length: {}\r\n\r\n", payload.size());
          DLOG("dap", "Received event: {}", payload);
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
  DLOG("dap", "posted event for msg with seq {}", serializable_event->response_seq);
  notify_new_message();
}

void
DAP::notify_new_message() noexcept
{
  PERFORM_ASSERT(posted_event_notifier.notify(), "failed to notify DAP interface of new message due to {}",
                 strerror(errno));
}

void
DAP::clean_up() noexcept
{
  using namespace std::chrono_literals;
  keep_running = false;
}

void
DAP::add_tty(int master_pty_fd) noexcept
{
  // todo(simon): when we add a new pty, what we need to do
  // is somehow find a way to re-route (temporarily) the other pty's to /dev/null, because we don't care for them
  // however, we must also be able to _restore_ those pty's from that re-routing. I'm not sure that works, or if
  // it's possible but it would be nice.
  auto flags = fcntl(master_pty_fd, F_GETFL);
  VERIFY(flags != -1, "Failed to get pty flags");
  VERIFY(fcntl(master_pty_fd, F_SETFL, flags | FNDELAY | FNONBLOCK) != -1, "Failed to set FNDELAY on pty");
  current_tty_idx = tty_fds.size();
  tty_fds.push_back(master_pty_fd);
}

std::optional<int>
DAP::current_tty() noexcept
{
  if (tty_fds.empty())
    return std::nullopt;
  return tty_fds[current_tty_idx];
}

} // namespace ui::dap