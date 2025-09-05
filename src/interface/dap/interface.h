/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <interface/dap/dap_defs.h>
#include <json/json.h>
#include <lib/arena_allocator.h>
#include <notify_pipe.h>
#include <tracee/util.h>
#include <utils/logger.h>
#include <utils/util.h>

// stdlib
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>

#include <vector>

namespace mdb {
class Tracer;
class TraceeController;
/* The different DAP commands/requests */
namespace alloc {
class ArenaResource;
}

namespace ui {
struct UIResult;
using UIResultPtr = const UIResult *;
} // namespace ui

namespace ui::dap {

struct LaunchResponse;
struct AttachResponse;

struct Event;

struct Request
{
  CommandType command;
  std::vector<std::string> arguments;
};

struct ParseBuffer
{
public:
  ParseBuffer(size_t size) noexcept : size{ 0, 0 }, buffer_size(size)
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
    const auto duration_ms = MilliSecondsSince(start);
    MDB_ASSERT(duration_ms < 1500, "Read took *way* too long");
    if (read_bytes == -1) {
      CDLOG(errno != EWOULDBLOCK && errno != EAGAIN,
        core,
        "command buffer read error: {} for fd {}",
        strerror(errno),
        fd);
      return false;
    }
    VERIFY(read_bytes >= 0,
      "Failed to read (max {} out of total {}) from parse buffer. Error: {}. Contents of buffer: '{}'",
      buffer_size - current_size(),
      buffer_size,
      strerror(errno),
      take_view());
    if (read_bytes >= 0) {
      size[current_buffer_index] += read_bytes;
    }
    return true;
  }

  std::string_view
  take_view() const noexcept
  {
    return std::string_view{ swap_buffers[current_buffer_index], current_size() };
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
    MDB_ASSERT(
      next_buffer_used < buffer_size, "Offset into buffer outside of {} bytes: {}", buffer_size, next_buffer_used);
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
  Launch,
  Attach,
  RR,
};

struct SupervisorEntry
{
  SessionId mSupervisorId;
  TraceeController *mSupervisor;

  constexpr auto operator<=>(const SupervisorEntry &) const = default;
};

struct InitializationState
{
  SessionId mPid;
  std::string mSessionId;
  UIResult *mLaunchOrAttachResponse;
};

class DebugAdapterClient
{
  int mReadFd{};
  int mWriteFd{};
  ParseBuffer mParseSwapBuffer{ MDB_PAGE_SIZE * 16 };
  int mTtyFileDescriptor{ -1 };
  std::vector<SupervisorEntry> mSupervisors;
  // The allocator that can be used by commands during execution of them, for temporary objects etc
  // UICommand upon destruction, calls mCommandsAllocator.Reset(), at which point all allocations beautifully melt
  // away.
  std::unique_ptr<alloc::ArenaResource> mCommandsAllocator;
  std::unique_ptr<alloc::ArenaResource> mCommandResponseAllocator;
  std::unique_ptr<alloc::ArenaResource> mEventsAllocator;

  std::vector<alloc::ArenaResource *> mCommandAllocatorPool;

  DebugAdapterClient(DapClientSession session, std::filesystem::path &&path, int socket_fd) noexcept;
  // Most likely used as the initial DA Client Connection (which tends to be via standard in/out, but don't have to
  // be.)
  DebugAdapterClient(DapClientSession session, int standard_in, int standard_out) noexcept;

  std::mutex m{};
  // Delayed events are used when we want to either delay and event or result or order events and results from a
  // command in a specific order. For instance, during attach/launch, there is non-trivial ordering in how events
  // need to be sent and received and this solves that problem.
  std::vector<UIResultPtr> mDelayedEvents{};
  std::vector<InitializationState> mSessionInit;

  void InitAllocators() noexcept;

public:
  static const char *gSocketPath;
  DapClientSession mSessionType;
  ~DebugAdapterClient() noexcept;

  alloc::ArenaResource *GetCommandArenaAllocator() noexcept;
  alloc::ArenaResource *GetResponseArenaAllocator() noexcept;
  static DebugAdapterClient *CreateStandardIOConnection() noexcept;
  // The path passed into this function can be (_should be_) leaked. Clean up at exit of process, and by leaking,
  // protections like atexit can work to remove the file, because it will always either exist, or not exist.
  // `acceptTimeout` is how long mdb will wait for a connection until it times out and exits.
  static DebugAdapterClient *CreateSocketConnection(const char *socketPath, int acceptTimeout) noexcept;
  std::unique_ptr<alloc::ScopedArenaAllocator> AcquireArena() noexcept;

  void AddSupervisor(TraceeController *tc) noexcept;
  void RemoveSupervisor(TraceeController *supervisor) noexcept;
  void PostDapEvent(ui::UIResultPtr event);

  int ReadFileDescriptor() const noexcept;
  int WriteFileDescriptor() const noexcept;

  void ConfigDone(SessionId processId) noexcept;

  bool WriteSerializedProtocolMessage(std::string_view output) const noexcept;
  void ReadPendingCommands() noexcept;
  void SetTtyOut(int fd, SessionId pid) noexcept;
  std::optional<int> GetTtyFileDescriptor() const noexcept;
  TraceeController *GetSupervisor(SessionId pid) const noexcept;
  std::span<const SupervisorEntry> Supervisors() const noexcept;
  void SetDebugAdapterSessionType(DapClientSession type) noexcept;
  void PushDelayedEvent(UIResultPtr delayedEvent) noexcept;
  void FlushEvents() noexcept;
  bool IsClosed() noexcept;
  bool SessionConfigurationDone(SessionId sessionId) noexcept;
};

enum class InterfaceNotificationSource
{
  DebugAdapterClient,
  ClientStdout
};

using DAPKey = std::uintptr_t;
using NotifSource = std::tuple<int, InterfaceNotificationSource, DebugAdapterClient *>;

struct DapNotification
{
  InterfaceNotificationSource mSource;
  SessionId mPid{ 0 };
};

struct StandardIo
{
  int mFd;
  // The process ID that outputs to it's standard IO
  SessionId mSessionId;
};

struct PollState
{
  std::vector<pollfd> fds{};
  std::unordered_map<int, DapNotification> map{};

  constexpr void
  Clear() noexcept
  {
    fds.clear();
    map.clear();
  }

  constexpr void
  ClearInit() noexcept
  {
    Clear();
  }

  constexpr void
  AddCommandSource(int fd) noexcept
  {
    fds.push_back({ .fd = fd, .events = POLLIN, .revents = 0 });
    map[fd] = DapNotification{ .mSource = InterfaceNotificationSource::DebugAdapterClient };
  }

  constexpr void
  AddStandardIOSource(int fd, SessionId processId) noexcept
  {
    fds.push_back({ .fd = fd, .events = POLLIN, .revents = 0 });
    map[fd] = DapNotification{ .mSource = InterfaceNotificationSource::ClientStdout, .mPid = processId };
  }

  constexpr auto
  ClientFds() noexcept
  {
    return std::span{ fds.begin(), fds.end() };
  }

  constexpr DapNotification
  Get(int fd) noexcept
  {
    return map[fd];
  }
};

class DapEventSystem
{
private:
  DebugAdapterClient *mClient;
  std::vector<StandardIo> mStandardIo;
  std::vector<DapNotification> mNewEvents;

  std::unique_ptr<alloc::ArenaResource> mTemporaryArena;

public:
  using StackAllocator = alloc::StackAllocator<2048>;
  bool WaitForEvents(PollState &state, std::vector<DapNotification> &events) noexcept;

  explicit DapEventSystem(DebugAdapterClient *client) noexcept;
  ~DapEventSystem() noexcept;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.

  void StartIOPolling(std::stop_token &token) noexcept;
  void SetClient(DebugAdapterClient *client) noexcept;
  void Poll(PollState &state) noexcept;
  void AddStandardIOSource(int fd, SessionId pid) noexcept;

  void CleanUp() noexcept;
  void FlushEvents() noexcept;

  void ConfigureTty(int master_pty_fd) noexcept;
  DebugAdapterClient *Get() const noexcept;

private:
  UIResultPtr PopEvent() noexcept;
  void WriteProtocolMessage(std::string_view msg) noexcept;

  mdb::Notifier::WriteEnd mPostedEventNotified;
  mdb::Notifier::ReadEnd mPostedEventListener;

  mdb::Notifier mNewClientNotifier;
  int mWriteFileDescriptor;
  // The buffer where we put output from the traced application, buffered to be sent to the Debug adapter client
  // (or whatever protocol or client we may support in the future.)
  char *mTraceeStandardOutBuffer;
  std::mutex mUIResultLock;
  std::deque<UIResultPtr> mEventsQueue;
};

void AtExit() noexcept;

}; // namespace ui::dap

} // namespace mdb