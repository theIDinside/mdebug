/** LICENSE TEMPLATE */
#include "interface.h"

// mdb
#include <common.h>
#include <event_queue.h>
#include <events/event.h>
#include <interface/dap/commands.h>
#include <interface/dap/events.h>
#include <interface/dap/parse_buffer.h>
#include <interface/tracee_command/supervisor_state.h>
#include <interface/ui_result.h>
#include <lib/arena_allocator.h>
#include <tracer.h>
#include <utils/signals.h>

// std
#include <algorithm>
#include <filesystem>
#include <memory>
#include <unordered_map>

// system
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

namespace mdb::ui::dap {
using namespace std::string_literals;

void
AtExit() noexcept
{
  if (DebugAdapterManager::gSocketPath) {
    unlink(DebugAdapterManager::gSocketPath);
  }
}

std::string_view
ContentDescriptor::payload() const noexcept
{
  return std::string_view{ payload_begin, payload_begin + payload_length };
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

DapEventSystem::DapEventSystem(DebugAdapterManager *client) noexcept
    : mClient(client), mWriteFileDescriptor(client->WriteFileDescriptor()), mUIResultLock{}, mEventsQueue{}
{
  auto [r, w] = mdb::Notifier::notify_pipe();
  mNewClientNotifier = mdb::Notifier::notify_pipe();
  mPostedEventNotified = w;
  mPostedEventListener = r;
  mTraceeStandardOutBuffer = mmap_buffer<char>(4096 * 3);
  mTemporaryArena = alloc::ArenaResource::CreateUniquePtr(alloc::Page{ 16 });
}

DapEventSystem::~DapEventSystem() noexcept {}

UIResultPtr
DapEventSystem::PopEvent() noexcept
{
  VERIFY(!mEventsQueue.empty(), "Can't pop events from an empty list!");
  std::lock_guard lock{ mUIResultLock };
  UIResultPtr evt = mEventsQueue.front();
  mEventsQueue.pop_front();
  return evt;
}

void
DapEventSystem::WriteProtocolMessage(std::string_view msg) noexcept
{
  const auto header = std::format("Content-Length: {}\r\n\r\n", msg.size());
  CDLOG(MDB_DEBUG == 1, dap, "WRITING -->{}{}<---", header, msg);
  const auto headerWrite = write(mWriteFileDescriptor, header.data(), header.size());
  VERIFY(headerWrite != -1 && headerWrite == static_cast<ssize_t>(header.size()),
    "Did not write entire header or some other error occured: {}",
    headerWrite);
  const auto msgWrite = write(mWriteFileDescriptor, msg.data(), msg.size());
  VERIFY(msgWrite != -1 && msgWrite == static_cast<ssize_t>(msg.size()),
    "Did not write entire message or some other error occured: {}",
    msgWrite);
}

void
DapEventSystem::SetClient(DebugAdapterManager *client) noexcept
{
  mClient = client;
}

void
DapEventSystem::StartIOPolling(std::stop_token &token) noexcept
{
  mdb::ScopedBlockedSignals blocked_sigs{ std::array{ SIGCHLD } };
  // TODO: Implement support to spawn the DAP client for a socket etc, instead of stdio
  Tracer::SetDebugAdapterManager(mClient);

  PollState state{};
  while (!token.stop_requested()) {
    Poll(state);
  }
}

void
DapEventSystem::AddStandardIOSource(int fd, SessionId pid) noexcept
{
  mStandardIo.push_back({ fd, pid });
}

bool
DapEventSystem::WaitForEvents(PollState &state, std::vector<DapNotification> &events) noexcept
{
  // TODO(simon): Change this to a stack allocated (or a memory arena from which we can pull the contiguous memory
  // from and then just leak back to the allocator)
  state.ClearInit();

  const auto fd = mClient->ReadFileDescriptor();
  state.AddCommandSource(fd);

  for (auto io : mStandardIo) {
    state.AddStandardIOSource(io.mFd, io.mSessionId);
  }

  if (poll(state.fds.data(), state.fds.size(), -1) <= 0) {
    return false;
  }

  for (const auto pollResult :
    state.ClientFds() | std::views::filter([](auto pfd) { return (pfd.revents & POLLIN) == POLLIN; })) {
    events.push_back(state.Get(pollResult.fd));
  }

  return !events.empty();
}

void
DapEventSystem::Poll(PollState &state) noexcept
{
  if (WaitForEvents(state, mNewEvents)) {
    for (auto &event : mNewEvents) {
      switch (event.mSource) {
      case InterfaceNotificationSource::DebugAdapterClient:
        mClient->ReadPendingCommands();
        break;
      case InterfaceNotificationSource::ClientStdout: {
        auto tty = mClient->GetTtyFileDescriptor();
        MDB_ASSERT(tty.has_value(), "DAP Client has invalid configuration");
        const auto bytes_read = read(*tty, mTraceeStandardOutBuffer, 4096 * 3);
        if (bytes_read == -1) {
          continue;
        }
        std::string_view data{ mTraceeStandardOutBuffer, static_cast<u64>(bytes_read) };
        mClient->WriteSerializedProtocolMessage(
          ui::dap::OutputEvent{ event.mPid, "stdout", std::string{ data } }.Serialize(
            0, mTemporaryArena->ScopeAllocation().GetAllocator()));
      } break;
      }
    }
  }

  mNewEvents.clear();
}

void
DebugAdapterManager::ReadPendingCommands() noexcept
{
  MDB_ASSERT(mReadFd != -1, "file descriptor for reading commands invalid: {}", mReadFd);
  if (!mParseSwapBuffer.expect_read_from_fd(mReadFd)) {
    return;
  }
  bool no_partials = false;
  const auto request_headers = ParseHeadersFromBuffer(mParseSwapBuffer.take_view(), &no_partials);

  const auto PushNewCommand = [&](const ContentParse &parse) {
    const auto *cd = std::get_if<ContentDescriptor>(&parse);
    auto cmd = ParseDebugAdapterCommand(*this, std::string{ cd->payload() });
    EventSystem::Get().PushCommand(this, std::move(cmd));
  };

  if (no_partials && request_headers.size() > 0) {
    for (auto &&hdr : request_headers) {
      PushNewCommand(hdr);
    }
    // since there's no partials left in the buffer, we reset it
    mParseSwapBuffer.clear();
  } else {
    if (request_headers.size() > 1) {
      for (auto i = 0ull; i < request_headers.size() - 1; i++) {
        PushNewCommand(request_headers[i]);
      }

      auto rd = std::get_if<RemainderData>(&request_headers.back());
      MDB_ASSERT(rd, "Parsed communication was not of type RemainderData");
      mParseSwapBuffer.swap(rd->offset);
      MDB_ASSERT(mParseSwapBuffer.current_size() == rd->length,
        "Parse Swap Buffer operation failed; expected length {} but got {}",
        rd->length,
        mParseSwapBuffer.current_size());
    }
  }
}

// Set the file descriptor to non-blocking mode
static bool
SetNonBlocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    return false;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    return false;
  }
  return true;
}

void
DebugAdapterManager::SetTtyOut(int fd, SessionId pid) noexcept
{
  MDB_ASSERT(mTtyFileDescriptor == -1, "TTY fd was already set!");
  mTtyFileDescriptor = fd;
  auto dap = Tracer::Get().GetDap();
  dap->ConfigureTty(fd);
  dap->AddStandardIOSource(fd, pid);
}

std::optional<int>
DebugAdapterManager::GetTtyFileDescriptor() const noexcept
{
  if (mTtyFileDescriptor != -1) {
    return mTtyFileDescriptor;
  }
  return {};
}

tc::SupervisorState *
DebugAdapterManager::GetSupervisor(Pid pid) const noexcept
{
  for (auto sv : mSupervisors) {
    if (sv->HasTask(pid)) {
      return sv;
    }
  }

  return nullptr;
}

void
DebugAdapterManager::SetDebugAdapterSessionType(DapClientSession type) noexcept
{
  mSessionType = type;
}

bool
DebugAdapterManager::IsClosed() noexcept
{
  return mReadFd == -1;
}

void
DebugAdapterManager::OnSessionConfiguredWithSupervisor(
  std::function<void(tc::SupervisorState &)> callback) noexcept
{
  mOnInitialSupervisor.push_back(std::move(callback));
}

bool
DebugAdapterManager::SupervisorMaterialized(NonNullPtr<tc::SupervisorState> supervisor) noexcept
{
  const bool configPhaseBeforeMaterialization = !mOnInitialSupervisor.empty();
  for (auto &cb : mOnInitialSupervisor) {
    cb(supervisor);
  }
  mOnInitialSupervisor.clear();
  return configPhaseBeforeMaterialization;
}

void
DebugAdapterManager::ConfigDoneWithNoSupervisor(bool value /* = true */) noexcept
{
  mConfigPhaseDoneWithNoMaterializedSupervisor = value;
}

void
DebugAdapterManager::PushDelayedEvent(UIResultPtr delayedEvent) noexcept
{
  std::lock_guard lock(m);
  mDelayedEvents.push_back(delayedEvent);
}

void
DebugAdapterManager::AddSupervisor(tc::SupervisorState *supervisor) noexcept
{
#ifdef MDB_DEBUG
  MDB_ASSERT(mdb::none_of_value(mSupervisors, supervisor), "Duplicate addition of supervisor");
#endif
  mSupervisors.push_back(supervisor);
}

void
DebugAdapterManager::RemoveSupervisor(tc::SupervisorState *supervisor) noexcept
{
  mSupervisors.erase(std::remove(mSupervisors.begin(), mSupervisors.end(), supervisor), mSupervisors.end());
}

void
DebugAdapterManager::FlushEvents() noexcept
{
  if (mDelayedEvents.empty()) {
    return;
  }

  auto scope = mEventsAllocator->ScopeAllocation();

  std::pmr::vector<UIResultPtr> tmp{ scope.GetAllocator() };
  constexpr auto maxToFlush = 64ul;
  tmp.reserve(maxToFlush);
  const auto count = std::min(mDelayedEvents.size(), maxToFlush);
  {
    std::lock_guard lock(m);
    std::copy(mDelayedEvents.begin(), mDelayedEvents.begin() + count, std::back_inserter(tmp));
    if (count == mDelayedEvents.size()) {
      mDelayedEvents.clear();
    } else {
      mDelayedEvents.erase(mDelayedEvents.begin(), mDelayedEvents.begin() + count);
    }
  }

  for (auto evt : tmp) {
    auto result = evt->Serialize(0, scope.GetAllocator());
    WriteSerializedProtocolMessage(result);
    delete evt;
  }
}

void
DapEventSystem::FlushEvents() noexcept
{
  auto tempAlloc = mTemporaryArena.get();
  while (!mEventsQueue.empty()) {
    auto evt = PopEvent();
    const auto protocol_msg = evt->Serialize(0, tempAlloc);
    WriteProtocolMessage(protocol_msg);
    delete evt;
  }
}

void
DapEventSystem::CleanUp() noexcept
{
  using namespace std::chrono_literals;
  FlushEvents();
}

DebugAdapterManager *
DapEventSystem::Get() const noexcept
{
  return mClient;
}

void
DapEventSystem::ConfigureTty(int master_pty_fd) noexcept
{
  // todo(simon): when we add a new pty, what we need to do
  // is somehow find a way to re-route (temporarily) the other pty's to /dev/null, because we don't care for them
  // however, we must also be able to _restore_ those pty's from that re-routing. I'm not sure that works, or if
  // it's possible but it would be nice.
  auto flags = fcntl(master_pty_fd, F_GETFL);
  VERIFY(flags != -1, "Failed to get pty flags");
  VERIFY(fcntl(master_pty_fd, F_SETFL, flags | FNDELAY | FNONBLOCK) != -1, "Failed to set FNDELAY on pty");
}

void
DebugAdapterManager::InitAllocators() noexcept
{
  using alloc::ArenaResource;
  using alloc::Page;

  mCommandsAllocator = ArenaResource::CreateUniquePtr(Page{ 16 });
  mCommandResponseAllocator = ArenaResource::CreateUniquePtr(Page{ 128 });
  mEventsAllocator = ArenaResource::CreateUniquePtr(Page{ 16 });
  for (auto i = 0; i < 512; ++i) {
    mCommandAllocatorPool.push_back(ArenaResource::Create(Page{ 32 }));
  }
}

DebugAdapterManager::DebugAdapterManager(
  DapClientSession type, int readFileDescriptor, int writeFileDescriptor) noexcept
    : mReadFd(readFileDescriptor), mWriteFd(writeFileDescriptor), mSessionType(type)
{
  InitAllocators();
}

DebugAdapterManager::~DebugAdapterManager() noexcept
{
  if (fs::exists(gSocketPath)) {
    unlink(gSocketPath);
    gSocketPath = nullptr;
    // means that in and out are of a socket, and not stdio
    close(mReadFd);
    close(mWriteFd);
  }
}

alloc::ArenaResource *
DebugAdapterManager::GetCommandArenaAllocator() noexcept
{
  return mCommandsAllocator.get();
}

alloc::ArenaResource *
DebugAdapterManager::GetResponseArenaAllocator() noexcept
{
  return mCommandResponseAllocator.get();
}

DebugAdapterManager *
DebugAdapterManager::CreateStandardIOConnection() noexcept
{
  VERIFY(SetNonBlocking(STDIN_FILENO), "Failed to set STDIN to non-blocking. Use a socket instead?");
  return new DebugAdapterManager{ DapClientSession::Launch, STDIN_FILENO, STDOUT_FILENO };
}

/* static */
DebugAdapterManager *
DebugAdapterManager::CreateSocketConnection(const char *socketPath, int acceptTimeout) noexcept
{
  bool DoCleanup = false;
  int serverFd = -1;
  int connectedClientFd = -1;

  ScopedDefer defer = [&]() {
    if (DoCleanup) {
      for (const auto fd : { serverFd, connectedClientFd }) {
        if (fd > 0) {
          close(fd);
        }
      }
      if (gSocketPath != nullptr) {
        unlink(gSocketPath);
        gSocketPath = nullptr;
      }
    }
  };
#define ERR_RET(condition, ...)                                                                                   \
  if ((condition)) {                                                                                              \
    DoCleanup = true;                                                                                             \
    DBGLOG(core, __VA_ARGS__);                                                                                    \
    std::println(__VA_ARGS__);                                                                                    \
    return nullptr;                                                                                               \
  }

  sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socketPath, sizeof(addr.sun_path) - 1);

  ERR_RET(std::filesystem::exists(socketPath), "Path already exists: {}", socketPath);

  serverFd = socket(AF_UNIX, SOCK_STREAM, 0);

  ERR_RET(serverFd < 0, "Failed to open socket: {}", strerror(errno))

  gSocketPath = socketPath;

  ERR_RET(bind(serverFd, (sockaddr *)&addr, sizeof(addr)) < 0,
    "Error: {}. Binding on server socket {} failed.",
    strerror(errno),
    serverFd);

  ERR_RET(listen(serverFd, 1) < 0, "Error: {}. Listening on server socket {} failed.", strerror(errno), serverFd);

  struct pollfd fds;
  fds.fd = serverFd;
  fds.events = POLLIN;

  int ret = poll(&fds, 1, acceptTimeout);
  ERR_RET(ret < 0, "Error: {}. Polling for incoming connections failed.", strerror(errno));
  ERR_RET(ret == 0, "Polling timed out waiting for clients. Exiting.");

  if (fds.revents & POLLIN) {
    connectedClientFd = accept(serverFd, nullptr, nullptr);
    ERR_RET(connectedClientFd < 0, "Error: {}. Accepting the client failed.", strerror(errno));

    if (!SetNonBlocking(connectedClientFd)) {
      ERR_RET(true, "Failed to set non-blocking for connected client file descriptor");
    }

    return new DebugAdapterManager{ DapClientSession::Launch, connectedClientFd, connectedClientFd };
  }

  return nullptr;
#undef ERR_RET
}

std::unique_ptr<alloc::ScopedArenaAllocator>
DebugAdapterManager::AcquireArena() noexcept
{
  MDB_ASSERT(!mCommandAllocatorPool.empty(), "No more allocators to take from the pool");
  auto alloc = mCommandAllocatorPool.back();
  mCommandAllocatorPool.pop_back();
  return std::make_unique<alloc::ScopedArenaAllocator>(alloc, &mCommandAllocatorPool);
}

void
DebugAdapterManager::PostDapEvent(ui::UIResultPtr event)
{
  // TODO(simon): I'm split on the idea if we should have one thread for each DebugAdapterClient, or like we do
  // now, 1 thread for all debug adapter client, that does it's dispatching vie the poll system calls. If we land,
  // 100% in the idea to keep it this way, we shouldn't really have to `new` and `delete` UIResultPtr's, that
  // should just be on the stack; but I'm keeping it here for now, in case I want to try out the other way.

  auto allocator = mEventsAllocator.get()->ScopeAllocation();
  auto result = event->Serialize(0, allocator);
  WriteSerializedProtocolMessage(result);
  delete event;
}

int
DebugAdapterManager::ReadFileDescriptor() const noexcept
{
  return mReadFd;
}
int
DebugAdapterManager::WriteFileDescriptor() const noexcept
{
  return mWriteFd;
}

static constexpr u32 ContentLengthHeaderLength = "Content-Length: "sv.size();

bool
DebugAdapterManager::WriteSerializedProtocolMessage(std::string_view output) const noexcept
{
  MDB_ASSERT(!output.empty(), "Ouptut is empty!");
  char header_buffer[128]{ "Content-Length: " };
  static constexpr auto header_end = "\r\n\r\n"sv;

  auto begin = header_buffer + ContentLengthHeaderLength;
  auto res = std::to_chars(begin, header_buffer + 128, output.size(), 10);
  MDB_ASSERT(res.ec == std::errc(), "Failed to append message size to content header");
  std::memcpy(res.ptr, header_end.data(), header_end.size());
  const auto header_length = static_cast<int>(res.ptr + header_end.size() - header_buffer);

  struct iovec iov[2];
  iov[0].iov_base = header_buffer;
  iov[0].iov_len = header_length;

  iov[1].iov_base = (void *)output.data();
  iov[1].iov_len = output.size();

  const auto header = std::format("Content-Length: {}\r\n\r\n", output.size());
#ifdef DEBUG
  DBGLOG(dap, "[write]:[{}{}]", header, output);
#endif

  const auto result = ::writev(mWriteFd, iov, 2);
  VERIFY(result == (header_length + static_cast<ssize_t>(output.size())),
    "Required flush-write but wrote partial content: {} out of {}",
    result,
    header_length + output.size());
  VERIFY(result != -1, "Expected succesful write to fd={}. msg='{}'", mWriteFd, output);
  return result >= static_cast<ssize_t>(output.size());
}

} // namespace mdb::ui::dap