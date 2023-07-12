#pragma once

#include "../../common.h"
#include "../../lib/spinlock.h"
#include "../../notify_pipe.h"
#include "../ui_result.h"
#include "dap_defs.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <linux/limits.h>
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

struct ParseBuffer
{
public:
  ParseBuffer(size_t size) noexcept : size{0, 0}
  {
    current_buffer_index = 0;
    swap_buffers[0] = mmap_buffer<const char>(size);
    swap_buffers[1] = mmap_buffer<const char>(size);
  }

  void
  read_from_fd(int fd) noexcept
  {
    auto read_bytes = read(fd, buffer_current(), 4096 - current_size());
    if (read_bytes >= 0) {
      size[current_buffer_index] += read_bytes;
    }
  }

  std::string_view
  take_view() const noexcept
  {
    return std::string_view{swap_buffers[current_buffer_index], current_size()};
  }

  // takes data from start .. end, copies it to the swap buffer and swaps buffers
  void
  swap(size_t start)
  {
    const auto next_buffer_used = size[current_buffer_index] - start;
    const auto src = buffer_ptr() + start;
    current_buffer_index = next_buffer_index();
    const auto dst = buffer_ptr();
    std::memcpy(dst, src, next_buffer_used);
    size[current_buffer_index] = next_buffer_used;
  }

  void
  clear() noexcept
  {
    size[0] = 0;
    size[1] = 0;
  }

  size_t
  current_size() const noexcept
  {
    return size[current_buffer_index];
  }

private:
  size_t
  next_buffer_index() const noexcept
  {
    return (current_buffer_index + 1) % 2;
  }

  char *
  buffer_ptr() noexcept
  {
    return const_cast<char *>(swap_buffers[current_buffer_index]);
  }

  char *
  buffer_current() noexcept
  {
    return const_cast<char *>(swap_buffers[current_buffer_index]) + size[current_buffer_index];
  }
  size_t size[2];
  const char *swap_buffers[2];
  size_t current_buffer_index;
};

class DAP
{
public:
  explicit DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd, int output_fd,
               utils::Notifier::WriteEnd io_write) noexcept;
  ~DAP() = default;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.
  void run_ui_loop();

  void post_event(UIResultPtr serializable_event) noexcept;
  void notify_new_message() noexcept;
  void clean_up() noexcept;
  // Fulfill the `UI` concept in ui_result.h
  void display_result(std::string_view str) const noexcept;

private:
  UIResultPtr pop_event() noexcept;
  void write_protocol_message(std::string_view msg) noexcept;
  u64 new_result_id() noexcept;

  utils::Notifier::WriteEnd posted_event_notifier;
  utils::Notifier::ReadEnd posted_evt_listener;
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
  std::deque<UIResultPtr> events_queue;
  u64 seq;
  bool cleaned_up = false;
  utils::Notifier::WriteEnd command_notifier;
  std::fstream log_file;
};
}; // namespace ui::dap