#include "interface.h"
#include "../../event_queue.h"
#include "../../tracer.h"
#include "../../utils/logger.h"
#include "../ui_result.h"
#include "commands.h"
#include "common.h"
#include "events.h"
#include "lib/lockguard.h"
#include "parse_buffer.h"
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <memory_resource>
#include <poll.h>
#include <random>
#include <supervisor.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <utils/signals.h>
namespace ui::dap {
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

constexpr pollfd
cfg_write_poll(int fd, int additional_flags) noexcept
{
  pollfd pfd{0, 0, 0};
  pfd.events = POLLOUT | additional_flags;
  pfd.fd = fd;
  return pfd;
}

constexpr pollfd
cfg_read_poll(int fd, int additional_flags) noexcept
{
  pollfd pfd{0, 0, 0};
  pfd.events = POLLIN | additional_flags;
  pfd.fd = fd;
  return pfd;
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

DAP::DAP(Tracer *tracer, int tracer_input_fd, int tracer_output_fd) noexcept
    : tracer{tracer}, tracer_in_fd(tracer_input_fd), tracer_out_fd(tracer_output_fd), keep_running(true),
      output_message_lock{}, events_queue{}, seq(0)
{
  auto [r, w] = utils::Notifier::notify_pipe();
  new_client_notifier = utils::Notifier::notify_pipe();
  posted_event_notifier = w;
  posted_evt_listener = r;
  tracee_stdout_buffer = mmap_buffer<char>(4096 * 3);
  sources.push_back({new_client_notifier.read.fd, InterfaceNotificationSource::NewClient, nullptr});
}

UIResultPtr
DAP::pop_event() noexcept
{
  VERIFY(!events_queue.empty(), "Can't pop events from an empty list!");
  LockGuard<SpinLock> lock{output_message_lock};
  UIResultPtr evt = events_queue.front();
  events_queue.pop_front();
  return evt;
}

void
DAP::write_protocol_message(std::string_view msg) noexcept
{
  const auto header = fmt::format("Content-Length: {}\r\n\r\n", msg.size());
  CDLOG(MDB_DEBUG == 1, dap, "WRITING -->{}{}<---", header, msg);
  VERIFY(write(tracer_out_fd, header.data(), header.size()) != -1, "Failed to write '{}'", header);
  VERIFY(write(tracer_out_fd, msg.data(), msg.size()) != -1, "Failed to write '{}'", msg);
}

void
DAP::start_interface() noexcept
{
  utils::ScopedBlockedSignals blocked_sigs{std::array{SIGCHLD}};
  new_client({.t = DebugAdapterClient::createStandardIOConnection()});

  while (keep_running) {
    one_poll(sources.size());
  }
}

void
DAP::init_poll(pollfd *fds)
{
  auto index = 0;
  for (const auto &[fd, src, client] : sources) {
    fds[index++] = pollfd{.fd = fd, .events = POLLIN, .revents = 0};
  }
}

void
DAP::add_source(NotifSource source) noexcept
{
  sources.push_back(source);
}

void
DAP::one_poll(u32 notifier_queue_size) noexcept
{
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wvla-cxx-extension"
  pollfd fds[notifier_queue_size];
  #pragma clang diagnostic pop
  init_poll(fds);
  auto ready = poll(fds, notifier_queue_size, 1000);
  VERIFY(ready != -1, "polling failed: {}", strerror(errno));
  if (ready == 0) {
    // no ready events
    return;
  }
  for (auto i = 0u; i < notifier_queue_size; ++i) {
    if ((fds[i].revents & POLLIN) == POLLIN) {
      auto [fd, source, client] = sources[i];
      switch (source) {
      case InterfaceNotificationSource::NewClient:
        // do nothing. We just need to be woken up, to start polling it.
        new_client_notifier.read.consume_expected();
        break;
      case InterfaceNotificationSource::DebugAdapterClient:
        client->commands_read();
        break;
      case InterfaceNotificationSource::ClientStdout: {
        auto tty = client->tty();
        ASSERT(tty.has_value(), "DAP Client has invalid configuration");
        const auto bytes_read = read(*tty, tracee_stdout_buffer, 4096 * 3);
        if (bytes_read == -1) {
          continue;
        }
        std::string_view data{tracee_stdout_buffer, static_cast<u64>(bytes_read)};
        client->write(ui::dap::OutputEvent{"stdout", std::string{data}}.serialize(0));
      } break;
      }
    }
  }
}

void
DAP::new_client(utils::OwningPointer<DebugAdapterClient> client)
{
  clients.push_back(client);
  add_source({client->read_fd(), InterfaceNotificationSource::DebugAdapterClient, client});
  new_client_notifier.write.notify();
}

void
DebugAdapterClient::commands_read() noexcept
{
  static constexpr auto DESCRIPTOR_STORAGE_SIZE = MDB_PAGE_SIZE;
  std::byte descriptor_buffer[sizeof(ContentDescriptor) * 15];
  std::pmr::monotonic_buffer_resource descriptor_resource{&descriptor_buffer, DESCRIPTOR_STORAGE_SIZE};

  parse_swapbuffer.expect_read_from_fd(in);
  bool no_partials = false;
  const auto request_headers = parse_headers_from(parse_swapbuffer.take_view(), descriptor_resource, &no_partials);
  if (no_partials && request_headers.size() > 0) {
    for (auto &&hdr : request_headers) {
      const auto cd = maybe_unwrap<ContentDescriptor>(hdr);
      const auto cmd = ParseDebugAdapterCommand(std::string{cd->payload()});

      push_command_event(this, cmd);
    }
    // since there's no partials left in the buffer, we reset it
    parse_swapbuffer.clear();
  } else {
    if (request_headers.size() > 1) {
      for (auto i = 0ull; i < request_headers.size() - 1; i++) {
        const auto cd = maybe_unwrap<ContentDescriptor>(request_headers[i]);
        const auto cmd = ParseDebugAdapterCommand(std::string{cd->payload()});
        push_command_event(this, cmd);
      }

      auto rd = maybe_unwrap<RemainderData>(request_headers.back());
      parse_swapbuffer.swap(rd->offset);
      ASSERT(parse_swapbuffer.current_size() == rd->length,
             "Parse Swap Buffer operation failed; expected length {} but got {}", rd->length,
             parse_swapbuffer.current_size());
    }
  }
}

void
DebugAdapterClient::set_tty_out(int fd) noexcept
{
  ASSERT(tty_fd == -1, "TTY fd was already set!");
  tty_fd = fd;
  auto dap = Tracer::Instance->dap;
  dap->configure_tty(fd);
  dap->add_source({fd, InterfaceNotificationSource::ClientStdout, this});
}

std::optional<int>
DebugAdapterClient::tty() const noexcept
{
  if (tty_fd != -1) {
    return tty_fd;
  }
  return {};
}

TraceeController *
DebugAdapterClient::supervisor() const noexcept
{
  return tc;
}

void
DebugAdapterClient::set_session_type(DapClientSession type) noexcept
{
  session_type = type;
}

void
DAP::notify_new_message() noexcept
{
  PERFORM_ASSERT(posted_event_notifier.notify(), "failed to notify DAP interface of new message due to {}",
                 strerror(errno));
}

void
DAP::flush_events() noexcept
{
  while (!events_queue.empty()) {
    auto evt = pop_event();
    const auto protocol_msg = evt->serialize(0);
    write_protocol_message(protocol_msg);
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
  return clients.front();
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

DebugAdapterClient::DebugAdapterClient(DapClientSession type, std::filesystem::path &&path, int socket) noexcept
    : socket_path(std::move(path)), in(socket), out(socket), session_type(type)
{
}

DebugAdapterClient::DebugAdapterClient(DapClientSession type, int standard_in, int standard_out) noexcept
    : in(standard_in), out(standard_out), session_type(type)
{
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
DebugAdapterClient::createSocketConnection(DebugAdapterClient *client) noexcept
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
    R"({{ "seq": 1, "type": "event", "event": "startDebugging", "body": {{ "configuration": {{ "path": "{}" }} }} }})",
    socket_path.c_str());

  client->write(reverseRequest);

  for (;;) {
    auto accepted = accept(socket_fd, nullptr, nullptr);
    if (accepted != -1) {
      return new DebugAdapterClient{child_session(client->session_type), std::move(socket_path), accepted};
    }
  }
}

DebugAdapterClient *
DebugAdapterClient::createStandardIOConnection() noexcept
{
  return new DebugAdapterClient{DapClientSession::None, STDIN_FILENO, STDOUT_FILENO};
}

void
DebugAdapterClient::client_configured(TraceeController *supervisor) noexcept
{
  tc = supervisor;
  tc->configure_dap_client(this);
}

void
DebugAdapterClient::post_event(ui::UIResultPtr event)
{
  // TODO(simon): I'm split on the idea if we should have one thread for each DebugAdapterClient, or like we do
  // now, 1 thread for all debug adapter client, that does it's dispatching vie the poll system calls. If we land,
  // 100% in the idea to keep it this way, we shouldn't really have to `new` and `delete` UIResultPtr's, that
  // should just be on the stack; but I'm keeping it here for now, in case I want to try out the other way.
  auto result = event->serialize(0);
  write(result);
  delete event;
}

int
DebugAdapterClient::read_fd() const noexcept
{
  return in;
}
int
DebugAdapterClient::out_fd() const noexcept
{
  return out;
}

static constexpr u32 ContentLengthHeaderLength = "Content-Length: "sv.size();

bool
DebugAdapterClient::write(std::string_view output) noexcept
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
      CDLOG(MDB_DEBUG == 1, dap, "[Process: {}] WRITING -->{}{}<---", tc->get_task_leader(), header, output);
    }
  }

  const auto result = ::writev(out, iov, 2);
  VERIFY(result != -1, "Expected succesful write to fd={}. msg='{}'", out, output);
  return result >= static_cast<ssize_t>(output.size());
}

} // namespace ui::dap