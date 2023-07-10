#pragma once

#include "../../common.h"
#include "../../lib/lockguard.h"
#include "../../lib/spinlock.h"
#include "dap_defs.h"
#include <algorithm>
#include <array>
#include <nlohmann/json.hpp>
#include <queue>

#include <string_view>
#include <sys/epoll.h>
#include <utility>
#include <variant>
#include <vector>
class Tracer;
/* The different DAP commands/requests */

namespace ui::dap {

struct Request
{
  Command command;
  std::vector<std::string> arguments;
};

class DAP
{
public:
  explicit DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd, int output_fd) noexcept;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.
  void run_ui_loop() noexcept;

  // Post `output_message` to the DAP output message queue
  void post_output_event(std::unique_ptr<std::string> output_message) noexcept;
  void post_json_event(nlohmann::json &&dictionary) noexcept;
  int get_post_event_fd() noexcept;
  void notify_new_message() noexcept;
  void kill_ui() noexcept;

  template <typename Fn>
  void
  handle_first_json(Fn handle) noexcept
  {
    VERIFY(!msg.empty(), "JSON Message queue must be non-empty");
    handle(msg.front());
    LockGuard<SpinLock> guard{output_message_lock};
    msg.pop_front();
  }

private:
  std::unique_ptr<std::string> pop_message() noexcept;

  Pipe post_event_fd;
  Tracer *tracer;
  int tracer_in_fd;
  int tracer_out_fd;
  int master_pty_fd;
  bool keep_running;
  char *buffer;
  char *tracee_stdout_buffer;
  SpinLock output_message_lock;
  std::deque<std::unique_ptr<std::string>> messages;
  std::deque<nlohmann::json> msg;
  int seq;
};
}; // namespace ui::dap