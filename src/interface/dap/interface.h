#pragma once

#include "../../lib/spinlock.h"
#include "../../notify_pipe.h"
#include "dap_defs.h"
#include <cstring>
#include <nlohmann/json.hpp>
#include <queue>
#include <string_view>
#include <typedefs.h>
#include <vector>
class Tracer;
/* The different DAP commands/requests */

namespace ui {
struct UIResult;
using UIResultPtr = const UIResult *;
} // namespace ui

namespace ui::dap {

struct Event;

struct Request
{
  CommandType command;
  std::vector<std::string> arguments;
};

struct ParseBuffer
{
public:
  ParseBuffer(size_t size) noexcept : size{0, 0}, buffer_size(size)
  {
    swap_buffers[0] = mmap_buffer<const char>(size);
    swap_buffers[1] = mmap_buffer<const char>(size);
  }

  // Expects to be able to read from `fd` - if we don't, we've got a bug and we should *not* silently ignore it or
  // handle it. Fail fast.
  void
  expect_read_from_fd(int fd) noexcept
  {
    VERIFY(current_size() < buffer_size, "Next read would read < 0 bytes!");
    auto read_bytes = read(fd, buffer_current(), buffer_size - current_size());
    VERIFY(read_bytes >= 0,
           "Failed to read (max {} out of total {}) from parse buffer. Error: {}. Contents of buffer: '{}'",
           buffer_size - current_size(), buffer_size, strerror(errno), take_view());
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
    size[current_buffer_index] = 0;
    current_buffer_index = next_buffer_index();
    const auto dst = buffer_ptr();
    ASSERT(next_buffer_used < buffer_size, "Offset into buffer outside of {} bytes: {}", buffer_size,
           next_buffer_used);
    if (next_buffer_used > 0) {
      std::memcpy(dst, src, next_buffer_used);
    }
    size[current_buffer_index] = next_buffer_used;
  }

  void
  clear() noexcept
  {
    current_buffer_index = 0;
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
    const auto ptr = swap_buffers[current_buffer_index];
    return const_cast<char *>(ptr);
  }

  char *
  buffer_current() noexcept
  {
    return const_cast<char *>(swap_buffers[current_buffer_index]) + size[current_buffer_index];
  }
  size_t size[2];
  const char *swap_buffers[2];
  size_t current_buffer_index = 0;
  const size_t buffer_size;
};

class DAP
{
private:
public:
  explicit DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd,
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
  void flush_events() noexcept;

  void add_tty(int master_pty_fd) noexcept;
  std::optional<int> current_tty() noexcept;

private:
  UIResultPtr pop_event() noexcept;
  void write_protocol_message(std::string_view msg) noexcept;

  // all the tty's we have connected.
  // Note that, we only ever listen/have one active at one time. Interleaving std output from different processes
  // would be insane.
  std::vector<int> tty_fds;
  u64 current_tty_idx;

  utils::Notifier::WriteEnd posted_event_notifier;
  utils::Notifier::ReadEnd posted_evt_listener;
  Tracer *tracer;
  int tracer_in_fd;
  int tracer_out_fd;
  bool keep_running;
  char *buffer;
  char *tracee_stdout_buffer;
  SpinLock output_message_lock;
  std::deque<UIResultPtr> events_queue;
  u64 seq;
  bool cleaned_up = false;
  utils::Notifier::WriteEnd command_notifier;
};
}; // namespace ui::dap