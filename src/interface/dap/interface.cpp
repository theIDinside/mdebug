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
#include <random>
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

DapClientSession
child_session(DapClientSession type) noexcept
{
  switch (type) {
  case DapClientSession::None:
    PANIC("No session type has been set.");
  case DapClientSession::Launch:
    return DapClientSession::LaunchedChildSession;
  case DapClientSession::Attach:
    return DapClientSession::AttachedChildSession;
  case DapClientSession::RR:
    return DapClientSession::RRChildSession;
  case DapClientSession::LaunchedChildSession:
  case DapClientSession::AttachedChildSession:
  case DapClientSession::RRChildSession:
    return type;
  }
  NEVER("Unknown DapClientSession type");
}

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
  mTemporaryArena = alloc::ArenaResource::Create(alloc::Page{16}, nullptr);
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
  VERIFY(headerWrite != -1 && headerWrite == header.size(),
         "Did not write entire header or some other error occured: {}", headerWrite);
  const auto msgWrite = write(mTracerOutputFileDescriptor, msg.data(), msg.size());
  VERIFY(msgWrite != -1 && msgWrite == msg.size(), "Did not write entire message or some other error occured: {}",
         msgWrite);
}

void
DAP::StartIOPolling(std::stop_token &token) noexcept
{
  mdb::ScopedBlockedSignals blocked_sigs{std::array{SIGCHLD}};
  NewClient({.t = DebugAdapterClient::CreateStandardIOConnection()});

  PollState state{};
  while (keep_running && !token.stop_requested()) {
    Poll(state);
  }
}

void
DAP::AddStandardIOSource(int fd, DebugAdapterClient *client) noexcept
{
  mStandardIo.push_back({fd, client});
}

bool
DAP::WaitForEvents(PollState &state, std::vector<DapNotification> &events) noexcept
{
  // TODO(simon): Change this to a stack allocated (or a memory arena from which we can pull the contiguous memory
  // from and then just leak back to the allocator)
  state.ClearInit(new_client_notifier.read.fd);

  for (auto client : mClients) {
    if (!client->IsClosed()) {
      const auto fd = client->ReadFileDescriptor();
      state.AddCommandSource(fd, client);
    }
  }

  for (auto io : mStandardIo) {
    state.AddStandardIOSource(io.mFd, io.mClient);
  }

  if (poll(state.fds.data(), state.fds.size(), -1) <= 0) {
    return false;
  }

  if ((state.fds[0].revents & POLLIN) == POLLIN) {
    new_client_notifier.read.consume_expected();
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
        if (event.mClient->IsClosed()) {
          RemoveSource(event.mClient);
          continue;
        }
        event.mClient->ReadPendingCommands();
        break;
      case InterfaceNotificationSource::ClientStdout: {
        auto tty = event.mClient->GetTtyFileDescriptor();
        ASSERT(tty.has_value(), "DAP Client has invalid configuration");
        const auto bytes_read = read(*tty, tracee_stdout_buffer, 4096 * 3);
        if (bytes_read == -1) {
          continue;
        }
        std::string_view data{tracee_stdout_buffer, static_cast<u64>(bytes_read)};
        event.mClient->WriteSerializedProtocolMessage(ui::dap::OutputEvent{"stdout", std::string{data}}.Serialize(
          0, mTemporaryArena->ScopeAllocation().GetAllocator()));
      } break;
      }
    }
  }

  mNewEvents.clear();
}

void
DAP::NewClient(mdb::OwningPointer<DebugAdapterClient> client)
{
  ASSERT(!std::ranges::any_of(mClients, [&client](auto p) { return p == client.t; }), "Already added client!");
  mClients.push_back(client);
  new_client_notifier.write.notify();
}

void
DebugAdapterClient::ReadPendingCommands() noexcept
{
  ASSERT(in != -1, "filedescriptor for DAP Client of process {} invalid", tc->TaskLeaderTid());
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
DebugAdapterClient::SetTtyOut(int fd) noexcept
{
  ASSERT(tty_fd == -1, "TTY fd was already set!");
  tty_fd = fd;
  auto dap = Tracer::Get().GetDap();
  dap->configure_tty(fd);
  dap->AddStandardIOSource(fd, this);
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
DebugAdapterClient::GetSupervisor() const noexcept
{
  return tc;
}

void
DebugAdapterClient::SetDebugAdapterSessionType(DapClientSession type) noexcept
{
  session_type = type;
}

bool
DebugAdapterClient::IsClosed() noexcept
{
  return in == -1;
}

void
DebugAdapterClient::ShutDown() noexcept
{
  FlushEvents();
  if (fs::exists(socket_path)) {
    unlink(socket_path.c_str());
    // means that in and out are of a socket, and not stdio
    if (in != -1) {
      close(in);
    }

    if (out != -1) {
      close(out);
    }
    in = -1;
    out = -1;
  }

  if (tty_fd != -1) {
    close(tty_fd);
  }
  tty_fd = -1;
  Tracer::Get().GetDap()->RemoveSource(this);
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
DebugAdapterClient::AddChild(DebugAdapterClient *child) noexcept
{
  mChildren.push_back(child);
}
void
DebugAdapterClient::RemoveChild(DebugAdapterClient *child) noexcept
{
  mChildren.erase(std::find(mChildren.begin(), mChildren.end(), child));
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
  keep_running = false;
  flush_events();
}

DebugAdapterClient *
DAP::main_connection() const noexcept
{
  return mClients.front();
}

void
DAP::RemoveSource(DebugAdapterClient *client) noexcept
{
  for (auto i = 0u; i < mClients.size(); ++i) {
    if (mClients[i] == client) {
      mShutdownClients.push_back(client);
      break;
    }
  }

  for (auto it = mStandardIo.begin(); it != std::end(mStandardIo); ++it) {
    if (it->mClient == client) {
      mStandardIo.erase(it);
      return;
    }
  }
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
  mCommandsAllocator = ArenaResource::Create(Page{16}, nullptr);
  mCommandResponseAllocator = ArenaResource::Create(Page{128}, nullptr);
  mEventsAllocator = ArenaResource::Create(Page{16}, nullptr);
}

DebugAdapterClient::DebugAdapterClient(DapClientSession type, std::filesystem::path &&path, int socket) noexcept
    : socket_path(std::move(path)), in(socket), out(socket), session_type(type)
{
  InitAllocators();
}

DebugAdapterClient::DebugAdapterClient(DapClientSession type, int standard_in, int standard_out) noexcept
    : in(standard_in), out(standard_out), session_type(type)
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

static std::string
generate_random_alphanumeric_string(size_t length)
{
  static constexpr std::string_view characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  std::string random_string;
  random_string.reserve(length);

  std::random_device rd;  // Seed for the random number engine
  std::mt19937 gen(rd()); // Standard mersenne_twister_engine
  std::uniform_int_distribution<> dis(0, characters.size() - 1);

  for (size_t i = 0; i < length; ++i) {
    random_string.push_back(characters[dis(gen)]);
  }

  return random_string;
}

/*static*/
DebugAdapterClient *
DebugAdapterClient::CreateSocketConnection(DebugAdapterClient &client) noexcept
{
  fs::path socket_path = fmt::format("/tmp/midas-{}", generate_random_alphanumeric_string(15));
  if (fs::exists(socket_path)) {
    if (unlink(socket_path.c_str()) == -1) {
      PANIC("Failed to unlink old socket path");
    }
  }
  auto socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un address;
  std::memset(&address, 0, sizeof(sockaddr_un));
  address.sun_family = AF_UNIX;
  std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1);
  if (bind(socket_fd, (sockaddr *)&address, sizeof(sockaddr_un)) == -1) {
    close(socket_fd);
    return nullptr;
  }

  if (listen(socket_fd, 1) == -1) {
    close(socket_fd);
    return nullptr;
  }

  auto reverseRequest = fmt::format(
    R"({{"seq":1,"type":"event","event":"startDebugging","body":{{"configuration":{{"path":"{}"}}}}}})",
    socket_path.c_str());

  client.WriteSerializedProtocolMessage(reverseRequest);

  for (;;) {
    auto accepted = accept(socket_fd, nullptr, nullptr);
    if (accepted != -1) {
      auto newClient =
        new DebugAdapterClient{child_session(client.session_type), std::move(socket_path), accepted};
      client.AddChild(newClient);
      return newClient;
    }
  }
  PANIC("Failed to set up child - this kind of error handling not yet implemented");
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
  return new DebugAdapterClient{DapClientSession::None, STDIN_FILENO, STDOUT_FILENO};
}

void
DebugAdapterClient::ClientConfigured(TraceeController *supervisor, bool alreadyAdded,
                                     std::optional<int> ttyFileDescriptor) noexcept
{
  if (!alreadyAdded) {
    Tracer::Get().GetDap()->NewClient({this});
  }

  tc = supervisor;
  tc->ConfigureDapClient(this);
  if (ttyFileDescriptor) {
    // set_tty_out(*ttyFileDescriptor);
  }
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
  if constexpr (MDB_DEBUG == 1) {
    if (tc == nullptr) {
      CDLOG(MDB_DEBUG == 1, dap, "[Partial DA] WRITING -->{}{}<---", header, output);
    } else {
      CDLOG(MDB_DEBUG == 1, dap, "[Process: {}] WRITING -->{}{}<---", tc->TaskLeaderTid(), header, output);
    }
  }

  const auto result = ::writev(out, iov, 2);
  VERIFY(result == (header_length + output.size()), "Required flush-write but wrote partial content: {} out of {}",
         result, header_length + output.size());
  VERIFY(result != -1, "Expected succesful write to fd={}. msg='{}'", out, output);
  return result >= static_cast<ssize_t>(output.size());
}

} // namespace mdb::ui::dap