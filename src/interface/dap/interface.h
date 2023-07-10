#pragma once

#include "../../common.h"
#include "../../lib/lockguard.h"
#include "../../lib/spinlock.h"
#include "dap_defs.h"
#include "events.h"
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

struct Event;

struct Request
{
  Command command;
  std::vector<std::string> arguments;
};

class DAP
{
public:
  explicit DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd, int output_fd) noexcept;
  ~DAP() = default;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.
  void run_ui_loop() noexcept;

  void post_event(Event *serializable_event) noexcept;
  int get_post_event_fd() noexcept;
  void notify_new_message() noexcept;
  void clean_up() noexcept;

private:
  Event *pop_event() noexcept;
  void write_protocol_message(const SerializedProtocolMessage &msg) noexcept;

  Pipe post_event_fd;
  Tracer *tracer;
  int tracer_in_fd;
  int tracer_out_fd;
  int master_pty_fd;
  bool keep_running;
  char *buffer;
  // A buffer of
  char *fmt_out_buffer;
  char *tracee_stdout_buffer;
  SpinLock output_message_lock;
  std::deque<Event *> events_queue;
  int seq;
  bool cleaned_up = false;
};
}; // namespace ui::dap