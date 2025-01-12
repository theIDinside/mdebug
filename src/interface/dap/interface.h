#pragma once

#include "../../notify_pipe.h"
#include "dap_defs.h"
#include "utils/util.h"
#include <chrono>
#include <cstring>
#include <nlohmann/json.hpp>
#include <queue>
#include <string_view>
#include <tracee/util.h>
#include <typedefs.h>
#include <vector>
class Tracer;
class TraceeController;
/* The different DAP commands/requests */
namespace alloc {
  class ArenaAllocator;
}


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
  bool
  expect_read_from_fd(int fd) noexcept
  {
    VERIFY(current_size() < buffer_size, "Next read would read < 0 bytes!");
    auto start = std::chrono::high_resolution_clock::now();
    auto read_bytes = read(fd, buffer_current(), buffer_size - current_size());
    const auto duration_ms =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start)
      .count();
    ASSERT(duration_ms < 1500, "Read took *way* too long");
    if(read_bytes == -1) {
      DBGLOG(core, "command buffer read error: {} for fd {}", strerror(errno), fd);
      return false;
    }
    VERIFY(read_bytes >= 0,
           "Failed to read (max {} out of total {}) from parse buffer. Error: {}. Contents of buffer: '{}'",
           buffer_size - current_size(), buffer_size, strerror(errno), take_view());
    if (read_bytes >= 0) {
      size[current_buffer_index] += read_bytes;
    }
    return true;
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

enum class DapClientSession
{
  // This is the strange world we live in.
  None,
  Launch,
  Attach,
  LaunchedChildSession,
  AttachedChildSession,
  RR,
  RRChildSession
};

DapClientSession child_session(DapClientSession type) noexcept;

class DebugAdapterClient
{
  std::filesystem::path socket_path{};
  int in{};
  int out{};
  ParseBuffer parse_swapbuffer{MDB_PAGE_SIZE * 16};
  int tty_fd{-1};
  TraceeController *tc{nullptr};
  // The allocator that can be used by commands during execution of them, for temporary objects etc
  // UICommand upon destruction, calls mCommandsAllocator.Reset(), at which point all allocations beautifully melt
  // away.
  std::unique_ptr<alloc::ArenaAllocator> mCommandsAllocator;
  std::unique_ptr<alloc::ArenaAllocator> mCommandResponseAllocator;
  std::unique_ptr<alloc::ArenaAllocator> mEventsAllocator;

  DebugAdapterClient(DapClientSession session, std::filesystem::path &&path, int socket_fd) noexcept;
  // Most likely used as the initial DA Client Connection (which tends to be via standard in/out, but don't have to
  // be.)
  DebugAdapterClient(DapClientSession session, int standard_in, int standard_out) noexcept;

  std::mutex m{};
  std::vector<UIResultPtr> mDelayedEvents{};

  void InitAllocators() noexcept;

public:
  DapClientSession session_type;
  ~DebugAdapterClient() noexcept;

  alloc::ArenaAllocator* GetCommandArenaAllocator() noexcept;
  alloc::ArenaAllocator* GetResponseArenaAllocator() noexcept;
  static DebugAdapterClient* createStandardIOConnection() noexcept;
  static DebugAdapterClient* createSocketConnection(const DebugAdapterClient &client) noexcept;
  void client_configured(TraceeController *tc, std::optional<int> ttyFileDescriptor = {}) noexcept;
  void PostEvent(ui::UIResultPtr event);

  int read_fd() const noexcept;
  int out_fd() const noexcept;

  bool write(std::string_view output) const noexcept;
  void commands_read() noexcept;
  void set_tty_out(int fd) noexcept;
  std::optional<int> tty() const noexcept;
  TraceeController *supervisor() const noexcept;
  void set_session_type(DapClientSession type) noexcept;
  void ShutDown() noexcept;
  void PushDelayedEvent(UIResultPtr delayedEvent) noexcept;
  void FlushEvents() noexcept;
};

enum class InterfaceNotificationSource
{
  NewClient,
  DebugAdapterClient,
  ClientStdout
};

using DAPKey = std::uintptr_t;
using NotifSource = std::tuple<int, InterfaceNotificationSource, DebugAdapterClient *>;

class DAP
{
private:
  std::vector<utils::OwningPointer<DebugAdapterClient>> clients{};
  std::vector<NotifSource> sources{};
  std::unique_ptr<alloc::ArenaAllocator> mTemporaryArena;

public:
  explicit DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd) noexcept;
  ~DAP() noexcept;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.
  void run_ui_loop();

  void start_interface() noexcept;
  void new_client(utils::OwningPointer<DebugAdapterClient> client);
  u32 notifiers_queue_size() const noexcept;
  void init_poll(pollfd *fds);
  void one_poll(u32 notifier_queue_size) noexcept;
  void add_source(NotifSource source) noexcept;

  void notify_new_message() noexcept;
  void clean_up() noexcept;
  void flush_events() noexcept;

  void configure_tty(int master_pty_fd) noexcept;
  DebugAdapterClient *main_connection() const noexcept;
  void RemoveSource(DebugAdapterClient* client) noexcept;
private:
  UIResultPtr pop_event() noexcept;
  void write_protocol_message(std::string_view msg) noexcept;

  utils::Notifier::WriteEnd posted_event_notifier;
  utils::Notifier::ReadEnd posted_evt_listener;

  utils::Notifier new_client_notifier;
  Tracer *tracer;
  int tracer_in_fd;
  int tracer_out_fd;
  bool keep_running;
  char *tracee_stdout_buffer;
  std::mutex mUIResultLock;
  std::deque<UIResultPtr> events_queue;
  u64 seq;
  bool cleaned_up = false;
};
}; // namespace ui::dap