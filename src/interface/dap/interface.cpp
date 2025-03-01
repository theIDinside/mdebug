/** LICENSE TEMPLATE */
#include "interface.h"
#include "../../event_queue.h"
#include "../../tracer.h"
#include "../ui_result.h"
#include "commands.h"
#include "common.h"
#include "events.h"
#include "lib/arena_allocator.h"
#include "parse_buffer.h"
#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <poll.h>
#include <supervisor.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <unordered_map>
#include <utils/signals.h>
#include <vector>
namespace mdb::ui::dap {
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

DAP::DAP(int tracerInputFileDescriptor, int tracerOutputFileDescriptor) noexcept
    : mTracerInputFileDescriptor(tracerInputFileDescriptor),
      mTracerOutputFileDescriptor(tracerOutputFileDescriptor), keep_running(true), mUIResultLock{}, events_queue{},
      seq(0)
{
  auto [r, w] = mdb::Notifier::notify_pipe();
  new_client_notifier = mdb::Notifier::notify_pipe();
  posted_event_notifier = w;
  posted_evt_listener = r;
  tracee_stdout_buffer = mmap_buffer<char>(4096 * 3);
  mTemporaryArena = alloc::ArenaResource::Create(alloc::Page{16});
}

DAP::~DAP() noexcept {}

UIResultPtr
DAP::pop_event() noexcept
{
  VERIFY(!events_queue.empty(), "Can't pop events from an empty list!");
  std::lock_guard lock{mUIResultLock};
  UIResultPtr evt = events_queue.front();
  events_queue.pop_front();
  return evt;
}

void
DAP::WriteProtocolMessage(std::string_view msg) noexcept
{
  const auto header = fmt::format("Content-Length: {}\r\n\r\n", msg.size());
  CDLOG(MDB_DEBUG == 1, dap, "WRITING -->{}{}<---", header, msg);
  const auto headerWrite = write(mTracerOutputFileDescriptor, header.data(), header.size());
  VERIFY(headerWrite != -1 && headerWrite == static_cast<ssize_t>(header.size()),
         "Did not write entire header or some other error occured: {}", headerWrite);
  const auto msgWrite = write(mTracerOutputFileDescriptor, msg.data(), msg.size());
  VERIFY(msgWrite != -1 && msgWrite == static_cast<ssize_t>(msg.size()),
         "Did not write entire message or some other error occured: {}", msgWrite);
}

void
DAP::SetClient(DebugAdapterClient *client) noexcept
{
  mClient = client;
}

void
DAP::StartIOPolling(std::stop_token &token) noexcept
{
  mdb::ScopedBlockedSignals blocked_sigs{std::array{SIGCHLD}};
  // TODO: Implement support to spawn the DAP client for a socket etc, instead of stdio
  SetClient(DebugAdapterClient::CreateStandardIOConnection());

  PollState state{};
  while (!token.stop_requested()) {
    Poll(state);
  }
}

void
DAP::AddStandardIOSource(int fd, Pid pid) noexcept
{
  mStandardIo.push_back({fd, pid});
}

bool
DAP::WaitForEvents(PollState &state, std::vector<DapNotification> &events) noexcept
{
  // TODO(simon): Change this to a stack allocated (or a memory arena from which we can pull the contiguous memory
  // from and then just leak back to the allocator)
  state.ClearInit();

  const auto fd = mClient->ReadFileDescriptor();
  state.AddCommandSource(fd);

  for (auto io : mStandardIo) {
    state.AddStandardIOSource(io.mFd, io.mPid);
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
DAP::Poll(PollState &state) noexcept
{
  if (WaitForEvents(state, mNewEvents)) {
    for (auto &event : mNewEvents) {
      switch (event.mSource) {
      case InterfaceNotificationSource::DebugAdapterClient:
        mClient->ReadPendingCommands();
        break;
      case InterfaceNotificationSource::ClientStdout: {
        auto tty = mClient->GetTtyFileDescriptor();
        ASSERT(tty.has_value(), "DAP Client has invalid configuration");
        const auto bytes_read = read(*tty, tracee_stdout_buffer, 4096 * 3);
        if (bytes_read == -1) {
          continue;
        }
        std::string_view data{tracee_stdout_buffer, static_cast<u64>(bytes_read)};
        mClient->WriteSerializedProtocolMessage(
          ui::dap::OutputEvent{event.mPid, "stdout", std::string{data}}.Serialize(
            0, mTemporaryArena->ScopeAllocation().GetAllocator()));
      } break;
      }
    }
  }

  mNewEvents.clear();
}

void
DebugAdapterClient::ReadPendingCommands() noexcept
{
  ASSERT(in != -1, "file descriptor for reading commands invalid: {}", in);
  if (!parse_swapbuffer.expect_read_from_fd(in)) {
    return;
  }
  bool no_partials = false;
  const auto request_headers = parse_headers_from(parse_swapbuffer.take_view(), &no_partials);
  if (no_partials && request_headers.size() > 0) {
    for (auto &&hdr : request_headers) {
      const auto cd = maybe_unwrap<ContentDescriptor>(hdr);
      const auto cmd = ParseDebugAdapterCommand(*this, std::string{cd->payload()});
      EventSystem::Get().PushCommand(this, cmd);
    }
    // since there's no partials left in the buffer, we reset it
    parse_swapbuffer.clear();
  } else {
    if (request_headers.size() > 1) {
      for (auto i = 0ull; i < request_headers.size() - 1; i++) {
        const auto cd = maybe_unwrap<ContentDescriptor>(request_headers[i]);
        const auto cmd = ParseDebugAdapterCommand(*this, std::string{cd->payload()});
        EventSystem::Get().PushCommand(this, cmd);
      }

      auto rd = maybe_unwrap<RemainderData>(request_headers.back());
      parse_swapbuffer.swap(rd->offset);
      ASSERT(parse_swapbuffer.current_size() == rd->length,
             "Parse Swap Buffer operation failed; expected length {} but got {}", rd->length,
             parse_swapbuffer.current_size());
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
DebugAdapterClient::SetTtyOut(int fd, Pid pid) noexcept
{
  ASSERT(tty_fd == -1, "TTY fd was already set!");
  tty_fd = fd;
  auto dap = Tracer::Get().GetDap();
  dap->configure_tty(fd);
  dap->AddStandardIOSource(fd, pid);
}

std::optional<int>
DebugAdapterClient::GetTtyFileDescriptor() const noexcept
{
  if (tty_fd != -1) {
    return tty_fd;
  }
  return {};
}

TraceeController *
DebugAdapterClient::GetSupervisor(Pid pid) const noexcept
{
  for (const auto entry : mSupervisors) {
    if (entry.mSupervisorId == pid) {
      return entry.mSupervisor;
    }
  }
  return nullptr;
}

void
DebugAdapterClient::SetDebugAdapterSessionType(DapClientSession type) noexcept
{
  mSessionType = type;
}

bool
DebugAdapterClient::IsClosed() noexcept
{
  return in == -1;
}

void
DebugAdapterClient::PushDelayedEvent(UIResultPtr delayedEvent) noexcept
{
  std::lock_guard lock(m);
  mDelayedEvents.push_back(delayedEvent);
}

void
DebugAdapterClient::FlushEvents() noexcept
{
  if (mDelayedEvents.empty()) {
    return;
  }

  UIResultPtr tmp[32];
  const auto count = std::min(mDelayedEvents.size(), std::size(tmp));
  {
    std::lock_guard lock(m);
    std::copy(mDelayedEvents.begin(), mDelayedEvents.begin() + count, tmp);
    if (count == mDelayedEvents.size()) {
      mDelayedEvents.clear();
    } else {
      mDelayedEvents.erase(mDelayedEvents.begin(), mDelayedEvents.begin() + count);
    }
  }

  for (auto evt : std::span{tmp, count}) {
    auto result = evt->Serialize(0, mEventsAllocator.get());
    WriteSerializedProtocolMessage(result);
    delete evt;
  }
}

void
DAP::flush_events() noexcept
{
  auto tempAlloc = mTemporaryArena.get();
  while (!events_queue.empty()) {
    auto evt = pop_event();
    const auto protocol_msg = evt->Serialize(0, tempAlloc);
    WriteProtocolMessage(protocol_msg);
    delete evt;
  }
}

void
DAP::clean_up() noexcept
{
  using namespace std::chrono_literals;
  flush_events();
}

DebugAdapterClient *
DAP::Get() const noexcept
{
  return mClient;
}

void
DAP::configure_tty(int master_pty_fd) noexcept
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
DebugAdapterClient::InitAllocators() noexcept
{
  using alloc::ArenaResource;
  using alloc::Page;

  // Create a 1 megabyte arena allocator.
  mCommandsAllocator = ArenaResource::Create(Page{16});
  mCommandResponseAllocator = ArenaResource::Create(Page{128});
  mEventsAllocator = ArenaResource::Create(Page{16});
}

DebugAdapterClient::DebugAdapterClient(DapClientSession type, std::filesystem::path &&path, int socket) noexcept
    : socket_path(std::move(path)), in(socket), out(socket), mSessionType(type)
{
  InitAllocators();
}

DebugAdapterClient::DebugAdapterClient(DapClientSession type, int standard_in, int standard_out) noexcept
    : in(standard_in), out(standard_out), mSessionType(type)
{
  InitAllocators();
}

DebugAdapterClient::~DebugAdapterClient() noexcept
{
  if (fs::exists(socket_path)) {
    unlink(socket_path.c_str());
    // means that in and out are of a socket, and not stdio
    close(in);
    close(out);
  }
}

alloc::ArenaResource *
DebugAdapterClient::GetCommandArenaAllocator() noexcept
{
  return mCommandsAllocator.get();
}

alloc::ArenaResource *
DebugAdapterClient::GetResponseArenaAllocator() noexcept
{
  return mCommandResponseAllocator.get();
}

DebugAdapterClient *
DebugAdapterClient::CreateStandardIOConnection() noexcept
{
  VERIFY(SetNonBlocking(STDIN_FILENO), "Failed to set STDIN to non-blocking. Use a socket instead?");
  return new DebugAdapterClient{DapClientSession::Launch, STDIN_FILENO, STDOUT_FILENO};
}

void
DebugAdapterClient::AddSupervisor(TraceeController *supervisor) noexcept
{
  mSupervisors.push_back({supervisor->TaskLeaderTid(), supervisor});
  supervisor->ConfigureDapClient(this);
}

void
DebugAdapterClient::RemoveSupervisor(TraceeController *supervisor) noexcept
{
  SupervisorEntry entry{supervisor->TaskLeaderTid(), supervisor};
  auto it = std::find(mSupervisors.begin(), mSupervisors.end(), entry);
  mSupervisors.erase(it);
}

void
DebugAdapterClient::PostDapEvent(ui::UIResultPtr event)
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
DebugAdapterClient::ReadFileDescriptor() const noexcept
{
  return in;
}
int
DebugAdapterClient::WriteFileDescriptor() const noexcept
{
  return out;
}

void
DebugAdapterClient::ConfigDone(Pid processId) noexcept
{
  auto it = std::find_if(mSessionInit.begin(), mSessionInit.end(),
                         [processId](const auto &e) { return e.mPid == processId; });

  ASSERT(it != std::end(mSessionInit), "No launch/attach response prepared for {}?", processId);
  if (it != std::end(mSessionInit)) {
    PushDelayedEvent(it->mLaunchOrAttachResponse);
  }

  DBGLOG(core, "Config done, removing prepared session.");

  mSessionInit.erase(it);
}

void
DebugAdapterClient::PrepareLaunch(std::string sessionId, Pid processId, LaunchResponse *launchResponse) noexcept
{
  mSessionType = DapClientSession::Launch;
  DBGLOG(core, "prepare initialization for session '{}' and process={}", sessionId, launchResponse->ProcessId());
  mSessionInit.push_back(InitializationState{processId, std::move(sessionId), launchResponse});
}

void
DebugAdapterClient::PrepareAttach(std::string sessionId, Pid processId, AttachResponse *attachResponse) noexcept
{
  mSessionType = DapClientSession::Attach;
  DBGLOG(core, "prepare initialization for session '{}' and process={}", sessionId, attachResponse->ProcessId());
  mSessionInit.push_back(InitializationState{processId, std::move(sessionId), attachResponse});
}

static constexpr u32 ContentLengthHeaderLength = "Content-Length: "sv.size();

bool
DebugAdapterClient::WriteSerializedProtocolMessage(std::string_view output) const noexcept
{
  char header_buffer[128]{"Content-Length: "};
  static constexpr auto header_end = "\r\n\r\n"sv;

  auto begin = header_buffer + ContentLengthHeaderLength;
  auto res = std::to_chars(begin, header_buffer + 128, output.size(), 10);
  ASSERT(res.ec == std::errc(), "Failed to append message size to content header");
  std::memcpy(res.ptr, header_end.data(), header_end.size());
  const auto header_length = static_cast<int>(res.ptr + header_end.size() - header_buffer);

  struct iovec iov[2];
  iov[0].iov_base = header_buffer;
  iov[0].iov_len = header_length;

  iov[1].iov_base = (void *)output.data();
  iov[1].iov_len = output.size();

  const auto header = fmt::format("Content-Length: {}\r\n\r\n", output.size());
#ifdef DEBUG
  DBGLOG(dap, "WRITING -->{}{}<---", header, output);
#endif

  const auto result = ::writev(out, iov, 2);
  VERIFY(result == (header_length + static_cast<ssize_t>(output.size())),
         "Required flush-write but wrote partial content: {} out of {}", result, header_length + output.size());
  VERIFY(result != -1, "Expected succesful write to fd={}. msg='{}'", out, output);
  return result >= static_cast<ssize_t>(output.size());
}

} // namespace mdb::ui::dap