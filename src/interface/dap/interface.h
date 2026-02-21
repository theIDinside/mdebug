/** LICENSE TEMPLATE */
#pragma once

// mdb
#include "utils/immutable.h"
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
class SessionBreakpoints;

namespace tc {
class SupervisorState;
}

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
  ParseBuffer(size_t size) noexcept : mBufferSize(size)
  {
    mSwapBuffers[0] = mmap_buffer<const char>(size);
    mSwapBuffers[1] = mmap_buffer<const char>(size);
  }

  // Expects to be able to read from `fd` - if we don't, we've got a bug and we should *not* silently ignore it or
  // handle it. Fail fast.
  bool
  ExpectReadFromFd(int fd) noexcept
  {
    VERIFY(CurrentSize() < mBufferSize, "Next read would read < 0 bytes!");
    auto start = std::chrono::high_resolution_clock::now();
    auto read_bytes = read(fd, CurrentBuffer(), mBufferSize - CurrentSize());
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
      mBufferSize - CurrentSize(),
      mBufferSize,
      strerror(errno),
      TakeView());
    if (read_bytes >= 0) {
      mSize[mCurrentBufferIndex] += read_bytes;
    }
    return true;
  }

  [[nodiscard]] std::string_view
  TakeView() const noexcept
  {
    return std::string_view{ mSwapBuffers[mCurrentBufferIndex], CurrentSize() };
  }

  // takes data from start .. end, copies it to the swap buffer and swaps buffers
  void
  Swap(size_t start)
  {
    const auto nextBufferUsed = mSize[mCurrentBufferIndex] - start;
    auto *const src = BufferPointer() + start;
    mSize[mCurrentBufferIndex] = 0;
    mCurrentBufferIndex = NextBufferIndex();
    auto *const dst = BufferPointer();
    MDB_ASSERT(
      nextBufferUsed < mBufferSize, "Offset into buffer outside of {} bytes: {}", mBufferSize, nextBufferUsed);
    if (nextBufferUsed > 0) {
      std::memcpy(dst, src, nextBufferUsed);
    }
    mSize[mCurrentBufferIndex] = nextBufferUsed;
  }

  void
  Clear() noexcept
  {
    mCurrentBufferIndex = 0;
    mSize[0] = 0;
    mSize[1] = 0;
  }

  [[nodiscard]] size_t
  CurrentSize() const noexcept
  {
    return mSize[mCurrentBufferIndex];
  }

private:
  [[nodiscard]] size_t
  NextBufferIndex() const noexcept
  {
    return (mCurrentBufferIndex + 1) % 2;
  }

  char *
  BufferPointer() noexcept
  {
    const auto *ptr = mSwapBuffers[mCurrentBufferIndex];
    return const_cast<char *>(ptr);
  }

  char *
  CurrentBuffer() noexcept
  {
    return const_cast<char *>(mSwapBuffers[mCurrentBufferIndex]) + mSize[mCurrentBufferIndex];
  }

  std::array<size_t, 2> mSize;
  std::array<const char *, 2> mSwapBuffers;
  size_t mCurrentBufferIndex = 0;
  const size_t mBufferSize;
};

enum class DapClientSession : u8
{
  Launch,
  Attach,
  RR,
};

class DebugAdapterSession
{
  // Until attach/launch, this will be nullptr
  // OnCreatedSupervisor hooks up the supervisor with the debug adapter sesssion.

public:
  bool HasAttachedOrLaunched() const noexcept;
  void OnCreatedSupervisor(NonNullPtr<tc::SupervisorState> supervisor) noexcept;
  bool ManagesSupervisor(Pid processId) const;
};

class DebugAdapterManager;

enum class ConfigureState : u8
{
  Initialized,
  Launched,
  Configured,
  Completed
};

class SupervisorSessionConfiguration
{
  using ConfigRequest = std::function<void(tc::SupervisorState &)>;

  // The supervisor which we're applying the configuration steps to.
  // The DebugAdapterManager maps a configToken -> DebugAdapterSessionConfiguration
  tc::SupervisorState *mSupervisor{ nullptr };
  // Apply when a process has been creatd, where this work can actually run.
  // In some scenarios, Launch happens first. Then this will never be filled with anything
  // because the requests can just run immediately.
  std::vector<ConfigRequest> mOnProcessCreated;

  ConfigureState mConfigureState{ ConfigureState::Initialized };

  void Complete();

public:
  static std::unique_ptr<SupervisorSessionConfiguration> Create();
  ConfigureState OnLaunch(NonNullPtr<tc::SupervisorState> supervisor);
  ConfigureState OnConfigurationDone();
  void AddConfigurationRequest(ConfigRequest &&request);
};

class DebugAdapterManager
{
  int mReadFd{};
  int mWriteFd{};
  ParseBuffer mParseSwapBuffer{ MDB_PAGE_SIZE * 16 };
  int mTtyFileDescriptor{ -1 };

  std::vector<tc::SupervisorState *> mSupervisors;
  // Callback for configuration phase to be executed when an actual supervisor has materialized
  // (which happens after a launch or attach). For processes that got spawed by the target, while debugging,
  // the configuration phase will work on the first try, since there's a materialized session to target.
  StringMap<Pid> mConfigTokenToProcessId;
  StringMap<std::unique_ptr<SupervisorSessionConfiguration>> mSessionConfigurations;

  // The allocator that can be used by commands during execution of them, for temporary objects etc
  // UICommand upon destruction, calls mCommandsAllocator.Reset(), at which point all allocations beautifully melt
  // away.
  std::unique_ptr<alloc::ArenaResource> mCommandsAllocator;
  std::unique_ptr<alloc::ArenaResource> mCommandResponseAllocator;
  std::unique_ptr<alloc::ArenaResource> mEventsAllocator;

  std::vector<alloc::ArenaResource *> mCommandAllocatorPool;

  DebugAdapterManager(DapClientSession session, std::filesystem::path &&path, int socket_fd) noexcept;
  // Most likely used as the initial DA Client Connection (which tends to be via standard in/out, but don't have to
  // be.)
  DebugAdapterManager(DapClientSession type, int readFileDescriptor, int writeFileDescriptor) noexcept;

  std::mutex m;
  // Delayed events are used when we want to either delay and event or result or order events and results from a
  // command in a specific order. For instance, during attach/launch, there is non-trivial ordering in how events
  // need to be sent and received and this solves that problem.
  std::vector<UIResultPtr> mDelayedEvents;

  void InitAllocators() noexcept;

public:
  static const char *gSocketPath;
  DapClientSession mSessionType;
  ~DebugAdapterManager() noexcept;

  alloc::ArenaResource *GetCommandArenaAllocator() noexcept;
  alloc::ArenaResource *GetResponseArenaAllocator() noexcept;
  static DebugAdapterManager *CreateStandardIOConnection() noexcept;
  // The path passed into this function can be (_should be_) leaked. Clean up at exit of process, and by leaking,
  // protections like atexit can work to remove the file, because it will always either exist, or not exist.
  // `acceptTimeout` is how long mdb will wait for a connection until it times out and exits.
  static DebugAdapterManager *CreateSocketConnection(const char *socketPath, int acceptTimeout) noexcept;
  std::unique_ptr<alloc::ScopedArenaAllocator> AcquireArena() noexcept;

  void PostDapEvent(ui::UIResultPtr event);

  int ReadFileDescriptor() const noexcept;
  int WriteFileDescriptor() const noexcept;

  void
  ConnectConfigToken(Pid processId, std::string_view configToken) noexcept
  {
    mConfigTokenToProcessId[std::string{ configToken }] = processId;
  }

  bool WriteSerializedProtocolMessage(std::string_view output) const noexcept;
  void ReadPendingCommands() noexcept;
  void SetTtyOut(int fd, SessionId pid) noexcept;
  std::optional<int> GetTtyFileDescriptor() const noexcept;
  tc::SupervisorState *GetSupervisor(Pid pid) const noexcept;
  void ConfigureNewSession(std::string_view configToken) noexcept;
  SupervisorSessionConfiguration *GetConfigurationFor(std::string_view configToken) noexcept;
  void SetDebugAdapterSessionType(DapClientSession type) noexcept;
  void PushDelayedEvent(UIResultPtr delayedEvent) noexcept;
  void AddSupervisor(tc::SupervisorState *supervisor) noexcept;
  void RemoveSupervisor(tc::SupervisorState *supervisor) noexcept;
  void FlushEvents() noexcept;
  bool IsClosed() const noexcept;

  // Called when configuration happens for a session with no running processes.
  void OnSessionConfiguredWithSupervisor(
    std::optional<std::string_view> configToken, std::function<void(tc::SupervisorState &)> callback) noexcept;
};

enum class InterfaceNotificationSource : u8
{
  DebugAdapterClient,
  ClientStdout
};

using DAPKey = std::uintptr_t;
using NotifSource = std::tuple<int, InterfaceNotificationSource, DebugAdapterManager *>;

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
  std::vector<pollfd> mFds;
  std::unordered_map<int, DapNotification> mMap;

  constexpr void
  Clear() noexcept
  {
    mFds.clear();
    mMap.clear();
  }

  constexpr void
  ClearInit() noexcept
  {
    Clear();
  }

  constexpr void
  AddCommandSource(int fd) noexcept
  {
    mFds.push_back({ .fd = fd, .events = POLLIN, .revents = 0 });
    mMap[fd] = DapNotification{ .mSource = InterfaceNotificationSource::DebugAdapterClient };
  }

  constexpr void
  AddStandardIOSource(int fd, SessionId processId) noexcept
  {
    mFds.push_back({ .fd = fd, .events = POLLIN, .revents = 0 });
    mMap[fd] = DapNotification{ .mSource = InterfaceNotificationSource::ClientStdout, .mPid = processId };
  }

  constexpr auto
  ClientFds() noexcept
  {
    return std::span{ mFds.begin(), mFds.end() };
  }

  constexpr DapNotification
  Get(int fd) noexcept
  {
    return mMap[fd];
  }
};

class DapEventSystem
{
private:
  DebugAdapterManager *mClient;
  std::vector<StandardIo> mStandardIo;
  std::vector<DapNotification> mNewEvents;

  std::unique_ptr<alloc::ArenaResource> mTemporaryArena;

public:
  using StackAllocator = alloc::StackAllocator<2048>;
  bool WaitForEvents(PollState &state, std::vector<DapNotification> &events) noexcept;

  explicit DapEventSystem(DebugAdapterManager *client) noexcept;
  ~DapEventSystem() noexcept;

  // After setup we call `infinite_poll` that does what the name suggests, polls for messages. We could say that
  // this function never returns, but that might not necessarily be the case. In a normal execution it will,
  // because this will be shut down when we shut down MDB, but if an error occur, we might want some cleanup at
  // which point we will have to return from this function since we have a hardline stance of *not* using
  // exceptions.

  void StartIOPolling(std::stop_token &token) noexcept;
  void SetClient(DebugAdapterManager *client) noexcept;
  void Poll(PollState &state) noexcept;
  void AddStandardIOSource(int fd, SessionId pid) noexcept;

  void CleanUp() noexcept;
  void FlushEvents() noexcept;

  static void ConfigureTty(int masterPtyFd) noexcept;
  [[nodiscard]] DebugAdapterManager *Get() const noexcept;

private:
  UIResultPtr PopEvent() noexcept;
  void WriteProtocolMessage(std::string_view msg) const noexcept;

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