// includes
#include "connection.h"
#include "shared.h"
#include "stopreply_parser.h"
// mdb workspace includes
#include <array>
#include <common.h>
#include <event_queue.h>
#include <initializer_list>
#include <notify_pipe.h>
#include <ptrace.h>
#include <string>
#include <tracer.h>
#include <type_traits>
#include <utils/enumerator.h>
#include <utils/expected.h>
#include <utils/logger.h>
#include <utils/pipes.h>
#include <utils/scope_defer.h>
#include <utils/scoped_fd.h>
#include <utils/sync_barrier.h>
#include <utils/util.h>
// system includes
#include <algorithm>
#include <arpa/inet.h>
#include <barrier>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <netinet/in.h>
#include <numeric>
#include <string_view>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <thread>
#include <unistd.h>

namespace gdb {
using Connection = RemoteConnection::ShrPtr;

std::unordered_map<std::string_view, TraceeStopReason> RemoteConnection::StopReasonMap{
    {{"watch", TraceeStopReason{valueOf("watch")}},
     {"rwatch", TraceeStopReason{valueOf("rwatch")}},
     {"awatch", TraceeStopReason{valueOf("awatch")}},
     {"syscall_entry", TraceeStopReason{valueOf("syscall_entry")}},
     {"syscall_return", TraceeStopReason{valueOf("syscall_return")}},
     {"library", TraceeStopReason{valueOf("library")}},
     {"replaylog", TraceeStopReason{valueOf("replaylog")}},
     {"swbreak", TraceeStopReason{valueOf("swbreak")}},
     {"hwbreak", TraceeStopReason{valueOf("hwbreak")}},
     {"fork", TraceeStopReason{valueOf("fork")}},
     {"vfork", TraceeStopReason{valueOf("vfork")}},
     {"vforkdone", TraceeStopReason{valueOf("vforkdone")}},
     {"exec", TraceeStopReason{valueOf("exec")}},
     {"clone", TraceeStopReason{valueOf("clone")}},
     {"create", TraceeStopReason{valueOf("create")}}}};

static constexpr SendError
send_err(const SendResult &res) noexcept
{
  switch (res.kind) {
  case SendResultKind::ResponseTimeout:
    return res.timeout;
  default:
    break;
  }
  return res.error;
};

std::pair<char, char>
checksum(std::string_view payload) noexcept
{
  // we don't increase `size` here, because we don't want '#' to be counted in the checksum
  u64 checksum_acc = static_cast<u64>(std::accumulate(payload.begin(), payload.end(), i64{0},
                                                      [](auto acc, char c) { return acc + i64{c}; })) %
                     256;
  ASSERT(checksum_acc <= UINT8_MAX, "Checksum incorrect");

  const auto [FirstIndex, SecondIndex] = HexIndices(static_cast<u8>(checksum_acc));
  return std::make_pair(HexDigits[FirstIndex], HexDigits[SecondIndex]);
}

RemoteConnection::RemoteConnection(std::string &&host, int port, utils::ScopedFd &&socket,
                                   RemoteSettings settings) noexcept
    : host(std::move(host)), port(port), socket(std::move(socket)), remote_settings(settings)
{
  auto r = ::pipe(request_command_fd);
  if (r == -1) {
    PANIC("Failed to create pipe for command requests");
  }
  r = ::pipe(received_async_notif_during_core_ctrl);
  if (r == -1) {
    PANIC("Failed to create pipe for command requests");
  }
}

RemoteConnection::~RemoteConnection() noexcept
{
  close(request_command_fd[0]);
  close(request_command_fd[1]);
  close(received_async_notif_during_core_ctrl[0]);
  close(received_async_notif_during_core_ctrl[1]);
}

BufferedSocket::BufferedSocket(utils::ScopedFd &&fd, u32 reserve_size) noexcept : fd_socket(std::move(fd))
{
  buffer.reserve(reserve_size);
}

bool
BufferedSocket::empty() const noexcept
{
  return buffer.size() - head == 0;
}

void
BufferedSocket::clear() noexcept
{
  head = 0;
  buffer.clear();
}

bool
BufferedSocket::ready(int timeout) const noexcept
{
  pollfd pfd[1];
  pfd[0].fd = fd_socket;
  pfd[0].events = POLLIN;
  auto ready = poll(pfd, 1, timeout);
  ASSERT(ready != -1, "poll system call failed on socket fd");
  return (pfd[0].revents & POLLIN) == POLLIN;
}

SendResult
BufferedSocket::write(std::string_view payload) noexcept
{
  u32 bytes_sent = 0;
  do {
    const auto send_res = send(fd_socket, payload.data(), payload.size(), 0);
    const auto success = send_res != -1;
    if (!success) {
      DLOG(LogChannel::remote, "failed sending {}", payload);
      return SystemError{.syserrno = errno};
    }
    bytes_sent += send_res;
  } while (bytes_sent < payload.size());

  DLOG(LogChannel::remote, "sent: '{}'", payload);
  return SentOk{};
}

SendResult
BufferedSocket::write_cmd(std::string_view payload) noexcept
{
  u32 bytes_sent = 0;
  char output_buf[payload.size() + 4];
  output_buf[0] = '$';
  u32 acc = 0;
  auto buf_sz = 1u;
  for (; buf_sz < payload.size() + 1; ++buf_sz) {
    char c = payload[buf_sz - 1];
    output_buf[buf_sz] = c;
    acc += c;
  }
  output_buf[buf_sz++] = '#';

  acc = acc % 256;
  u8 csum = acc;
  output_buf[buf_sz++] = HexDigits[(csum & 0xf0) >> 4];
  output_buf[buf_sz++] = HexDigits[(csum & 0xf)];
  ASSERT(buf_sz == payload.size() + 4, "Unexpected buffer length");

  do {
    const auto send_res = send(fd_socket, output_buf, buf_sz, 0);
    const auto success = send_res != -1;
    if (!success) {
      DLOG(LogChannel::remote, "failed sending {}", payload);
      return SystemError{.syserrno = errno};
    }
    bytes_sent += send_res;
  } while (bytes_sent < payload.size());

  DLOG(LogChannel::remote, "sent: '{}'", payload);
  return SentOk{};
}

std::optional<std::string>
BufferedSocket::read_payload() noexcept
{
  if (head == buffer.size() || buffer.empty()) {
    buffer_n(4096);
  }

  auto pos = find('$').transform([](auto value) { return value + 1; }).value_or(0);
  auto end = find('#');

  bool size_determined = false;

  while (!size_determined) {
    // URGENT TODO(implement escape parsing, very important)
    if (end) {
      size_determined = true;
    } else {
      const auto r = buffer_n(4096);
      if (r == 0) {
        return {};
      }
      end = find('#');
    }
  }

  std::string result{};
  result.reserve(end.value() - pos);
  std::copy(cbegin() + pos, cbegin() + end.value(), std::back_inserter(result));
  consume_n(end.transform([](auto value) { return value + 3; }).value());

  return result;
}

char
BufferedSocket::read_char() noexcept
{
  if (head == buffer.size() || buffer.empty()) {
    buffer_n(4096);
  }

  const auto result = buffer[head];
  consume_n(1);
  return result;
}

char
BufferedSocket::peek_char() noexcept
{
  if (size() == 0)
    return 0;
  return buffer[head];
}

u32
BufferedSocket::buffer_n(u32 requested) noexcept
{
  char buf[requested];
  auto can_read = ready(1);
  if (!can_read)
    return 0;
  if (const auto res = read(fd_socket, buf, requested); res != -1) {
    std::copy(buf, buf + res, std::back_inserter(buffer));
    return res;
  } else {
    PANIC("Failed to read from socket");
  }
}

u32
BufferedSocket::buffer_n_timeout(u32 requested, int timeout) noexcept
{
  auto can_read = ready(timeout);
  if (!can_read) {
    return 0;
  } else {
    char buf[requested];
    if (const auto res = read(fd_socket, buf, requested); res != -1) {
      std::copy(buf, buf + res, std::back_inserter(buffer));
      return res;
    } else {
      PANIC("Failed to read from socket");
    }
  }
}

bool
BufferedSocket::has_more_poll_if_empty(int timeout) const noexcept
{
  return size() > 0 || ready(timeout);
}

void
BufferedSocket::consume_n(u32 n) noexcept
{
  ASSERT(n + head <= buffer.size(), "Consuming n={} bytes when there's only {} left", n, buffer.size() - head);
  if (head + n == buffer.size()) {
    clear();
  } else {
    head += n;
  }
}

std::optional<MessageElement>
BufferedSocket::next_message(int timeout) noexcept
{
  u32 pos = 0;

  if (size() == 0) {
    if (buffer_n_timeout(4096, timeout) == 0) {
      return {};
    }
  }
  auto ch = at_unchecked(pos);
  const auto isPayloadKind = [&](auto ch) { return ch >= 35 && ch <= 45; };

  while (!isPayloadKind(ch)) {
    ++pos;
    if (pos >= size()) {
      if (buffer_n_timeout(4096, timeout) == 0) {
        // Means buffer returned 0, due to timeout
        return {};
      }
    } else {
      ch = at_unchecked(pos);
    }
  }

  return MessageElement{.pos = pos, .data = static_cast<MessageData>(ch)};
}

std::optional<u32>
BufferedSocket::find(char c) const noexcept
{
  auto it = std::find(cbegin(), cend(), c);
  if (it == std::end(buffer)) {
    return std::nullopt;
  }

  return std::distance(cbegin(), it);
}

std::optional<u32>
BufferedSocket::find_timeout(char ch, int timeout) noexcept
{
  if (const auto res = find(ch); res) {
    return res;
  }
  const auto sz = size();
  if (buffer_n_timeout(4096, timeout) == 0) {
    return {};
  }
  return find_from(ch, sz);
}

std::optional<u32>
BufferedSocket::find_from(char c, u32 pos) const noexcept
{
  if (pos >= size()) {
    return {};
  }

  auto it = std::find(cbegin() + pos, cend(), c);

  if (it == std::end(buffer)) {
    return {};
  }

  return std::distance(cbegin(), it);
}

std::optional<std::pair<u32, bool>>
BufferedSocket::find_ack() const noexcept
{
  const auto e = cend();
  auto it = cbegin();
  for (; it != e; ++it) {
    auto ch = *it;
    switch (ch) {
    case '+': {
      u32 idx = std::distance(cbegin(), it);
      return std::make_optional<std::pair<u32, bool>>(idx, true);
    }
    case '-': {
      u32 idx = std::distance(cbegin(), it);
      return std::make_optional<std::pair<u32, bool>>(idx, false);
    }
    default:
      break;
    }
  }
  return {};
}

utils::Expected<std::pair<u32, bool>, Timeout>
BufferedSocket::wait_for_ack(int timeout) noexcept
{
  bool no_more_no_ack_found = false;
  while (!no_more_no_ack_found) {
    auto ack = find_ack();
    if (!ack) {
      no_more_no_ack_found = buffer_n_timeout(4096, timeout) == 0;
    } else {
      return *ack;
    }
  }

  return Timeout{.msg = "Waiting for ACK timed out"};
}

std::optional<char>
BufferedSocket::at(u32 index) const noexcept
{
  if (index >= size()) {
    return {};
  }

  return *(cbegin() + index);
}

char
BufferedSocket::at_unchecked(u32 index) const noexcept
{
  return buffer[head + index];
}

void
take_wait(std::unique_ptr<utils::BarrierWait> &&b)
{
  (void)b;
}

/*static*/
utils::Expected<Connection, ConnectError>
RemoteConnection::connect(const std::string &host, int port,
                          std::optional<RemoteSettings> remote_settings) noexcept
{
  // returns a Expected<ScopedFd, ConnectError>. Transform it into Expected<Connection, ConnectError>
  return utils::ScopedFd::socket_connect(host, port)
      .and_then<InitError>([&](auto &&socket) -> utils::Expected<Connection, InitError> {
        std::shared_ptr<RemoteConnection> connection = std::make_shared<RemoteConnection>(
            std::string{host}, port, std::move(socket), remote_settings.value_or(RemoteSettings{}));

        return connection;
      });
}

void
RemoteConnection::consume_poll_events(int fd) noexcept
{
  ASSERT(fd == request_command_fd[0] || fd == received_async_notif_during_core_ctrl[0],
         "File descriptor not expected");
  char buf[128];
  const auto bytes_read = ::read(fd, buf, 128);
  if (bytes_read == -1) {
    PANIC("failed to consume poll events from fd")
  }
}

void
RemoteConnection::request_control() noexcept
{
  std::lock_guard lock(tracee_control_mutex);

  auto tries = 0;
  while (::write(request_command_fd[1], "+", 1) == -1 && tries++ < 10) {
  }
  if (tries >= 10) {
    PANIC("failed while requesting control over remote connection socket");
  }
  give_ctrl_sync.arrive_and_wait();
}

class PollSetup
{
  int socket;
  int cmd_request;
  int async_pending;
  pollfd fds[3];

public:
  enum class PolledEvent : i8
  {
    None = -1,
    HasIo = 0,
    AsyncPending = 1,
    // A remote controller has requested control and is awaiting `RemoteConnection` to relinquish control of the
    // socket/connection.
    CmdRequested = 2
  };

  PollSetup(int conn_socket, int cmds, int async) noexcept
      : socket(conn_socket), cmd_request(cmds), async_pending(async)
  {
    fds[0] = {socket, POLLIN, 0};
    fds[1] = {async_pending, POLLIN, 0};
    fds[2] = {cmd_request, POLLIN, 0};
  }

  constexpr auto
  fd_count() noexcept
  {
    return sizeof(fds) / sizeof(pollfd);
  }

  PolledEvent
  poll(std::optional<int> timeout) noexcept
  {
    static constexpr auto Channels = std::to_array<std::string_view>({"IO", "Async", "User command request"});
    static constexpr auto Event =
        std::to_array<PolledEvent>({PolledEvent::HasIo, PolledEvent::AsyncPending, PolledEvent::CmdRequested});

    const auto pull_evt = [&](auto pollfd) {
      if (pollfd.fd == fds[0].fd)
        return true;
      char c;
      return ::read(pollfd.fd, &c, 1) != -1;
    };
    const auto count = ::poll(fds, fd_count(), timeout.value_or(-1));
    if (count == -1 || count == 0) {
      return PolledEvent::None;
    }

    for (auto i = 0; i < 3; ++i) {
      if ((fds[i].revents & POLLIN) == POLLIN) {
        VERIFY(pull_evt(fds[i]), "Expected consumption of one '+' to succeed on: '{}'", Channels[i]);
        return Event[i];
      }
    }
    return PolledEvent::None;
  }
};

consteval auto
None()
{
  return std::nullopt;
}

struct Payload
{
  enum class Type
  {
    Ack,
    Nack,
    AsyncNotif,
    Normal,
    Empty
  } type;
  std::string_view payload;
};

void
RemoteConnection::write_ack() noexcept
{
  auto tries = 0;
  while (true && tries < 10) {
    const auto res = socket.write("+").is_ok();
    if (res) {
      break;
    } else {
      ++tries;
    }
  }
  if (tries == 10) {
    PANIC("failed to ack ");
  }
}

void
RemoteConnection::read_packets() noexcept
{
  do {
    if (const auto data = socket.read_payload(); data) {
      if (!remote_settings.is_noack) {
        write_ack();
      }
      DBGLOG(remote, "received: {}", *data);
      switch (message_type(*data)) {
      case MessageType::StopReply:
        process_stop_reply_payload(*data, false);
        break;
      case MessageType::CommandResponse:
        break;
      }
    }
  } while (socket.size() > 0 || socket.has_more_poll_if_empty(1));
}

std::optional<std::string>
RemoteConnection::take_pending() noexcept
{
  std::optional<std::string> result = std::nullopt;
  result.swap(pending_notification);
  return result;
}

/*static*/ std::optional<int>
RemoteConnection::parse_hexdigits(std::string_view input) noexcept
{
  int value;
  const auto [ptr, ec] = std::from_chars(input.data(), input.data() + input.size(), value, 16);
  if (ec == std::errc()) {
    return value;
  } else {
    return {};
  }
}

enum class TArgKinds
{
  Register,
  Thread,
  Core,
  StopReason,
  Unknown
};

namespace TArg {

struct Register
{
  int reg_num;
};

struct Thread
{
};
struct Core
{
};

} // namespace TArg

void
RemoteConnection::put_pending_notification(std::string_view payload) noexcept
{
  ASSERT(!pending_notification.has_value(), "Pending notification has not been consumed");
  pending_notification.emplace(payload);
  auto retries = 0;
  while (write(received_async_notif_during_core_ctrl[1], "+", 1) == -1 && retries < 10) {
    ++retries;
  }
  if (retries >= 10) {
    PANIC("Failed to write notification to async notif pipe");
  }
}

bool
RemoteConnection::process_task_received_signal_extended(int signal, std::string_view payload,
                                                        bool is_session_config) noexcept
{
  auto params = utils::split_string(payload, ";");
  WaitEventParser parser{*this};
  parser.control_kind_is_attached = is_session_config;
  parser.signal = signal;

  static constexpr auto DecodeBufferSize = 64;
  char dec_buf[DecodeBufferSize];

  for (const auto param_str : params) {
    const auto pos = param_str.find(':');
    const auto arg = param_str.substr(0, pos);
    auto val = param_str.substr(pos + 1);
    if (arg == "thread") {
      parser.parse_pid_tid(val);
    } else if (arg == "core") {
      parser.parse_core(val);
    } else {
      const auto maybeStopReason = valueOf(arg);
      if (parser.is_stop_reason(maybeStopReason)) {
        auto reason = static_cast<TraceeStopReason>(maybeStopReason);
        parser.parse_stop_reason(reason, val);
      } else {
        const auto register_number = RemoteConnection::parse_hexdigits(arg);
        auto contents = val;

        auto decoded = gdb::decode_rle_to_str(contents, dec_buf, DecodeBufferSize);
        auto &[no, reg_contents] = parser.registers.emplace_back(register_number.value(), std::vector<u8>{});
        reg_contents.reserve(decoded.length() / 2);
        const auto sz = decoded.size();
        for (auto i = 0u; i < sz; i += 2) {
          reg_contents.push_back(utils::fromhex(decoded[i]) * 16 + utils::fromhex(decoded[i + 1]));
        }
      }
    }
  }

  if (!is_session_config) {
    push_debugger_event(parser.new_debugger_event(false));
  } else {
    push_init_event(parser.new_debugger_event(true));
  }

  return true;
}

bool
RemoteConnection::process_stop_reply_payload(std::string_view received_payload, bool is_session_config) noexcept
{
  DBGLOG(remote, "Stop reply payload: {}", received_payload);
  ASSERT(!received_payload.empty(), "Expected a non-empty payload!");
  if (received_payload.front() == '$') {
    received_payload.remove_prefix(1);
  }

  StopReplyParser parser{settings(), received_payload};
  const auto kind = parser.stop_reply_kind();
  switch (kind) {
  case 'S': {
    TODO("S is a stop reply we don't yet support");
  }
  case 'T': {
    const auto signal = parser.parse_signal();
    ASSERT(signal.has_value(), "Expected to have at least the signal data");
    if (!signal) {
      DLOG(logging::Channel::remote, "Failed to parse signal for T packet: '{}'", received_payload);
      return false;
    }
    process_task_received_signal_extended(signal.value(), parser.parse_data, is_session_config);
    break;
  }
  case 'W': {
    const auto [target, exit_code] = parser.parse_exited<'W'>();
    if (!exit_code || !target) {
      return false;
    }
    push_debugger_event(CoreEvent::ProcessExitEvent(target.value(), target.value(), exit_code.value(), {}));
    break;
  }
  case 'X': {
    const auto [target, signal] = parser.parse_exited<'X'>();
    if (!signal || !target) {
      return false;
    }
    TODO("Add Terminated event or make ProcessExit have two variants (i like this better)");
    push_debugger_event(CoreEvent::ProcessExitEvent(target.value(), target.value(), signal.value(), {}));
    break;
  }
  case 'w': {
    if (const auto res = parser.parse_thread_exited(); res) {
      const auto &[pid, tid, code] = res.value();
      // If we're not non-stop, this will stop the entire process
      const auto process_needs_resuming = !remote_settings.is_non_stop;
      push_debugger_event(
          CoreEvent::ThreadExited({.target = pid, .tid = tid, .sig_or_code = code}, process_needs_resuming, {}));
      return true;
    } else {
      return false;
    }
  }
  case 'N':
    TODO("N packet is not yet implemented ")
  case 'O':
    TODO("the O packet is not yet implemented");
    break;
  }
  return true;
}

void
RemoteConnection::parse_event_consume_remaining() noexcept
{
  auto pending = take_pending();
  ASSERT(pending.has_value(), "No pending notification has been read");
  if (!remote_settings.is_non_stop) {
    auto payload = std::string_view{pending.value()};
    ASSERT(payload[0] == '$', "Expected 'synchronous non-stop' stop reply but got {}", payload[0]);
    payload.remove_prefix(1);
    process_stop_reply_payload(payload, false);
    // We are done. We are not in non-stop mode, there will be no further rapports.
    return;
  }
  auto payload = std::string_view{pending.value()};
  ASSERT(payload[0] == '%', "Expected Notification Header");
  payload.remove_prefix(1);
  ASSERT(payload.substr(0, 5) == "Stop:", "Only 'Stop' notifications are defined by the protocol as of yet");
  payload.remove_prefix(5);

  const auto sendRes = socket.write_cmd("vStopped");
  if (!sendRes.is_ok()) {
    PANIC(fmt::format("Failed to acknowledge asynchronous notification: {}", payload));
  }

  process_stop_reply_payload(payload, false);

  do {
    auto data = socket.read_payload();
    if (data == "OK") {
      return;
    }
    process_stop_reply_payload(payload, false);
    const auto sendRes = socket.write("vStopped");
    if (!sendRes.is_ok()) {
      PANIC(fmt::format("Failed to acknowledge asynchronous notification: {}", payload));
    }
  } while (socket.has_more_poll_if_empty(10));
}

void
RemoteConnection::relinquish_control_to_core() noexcept
{
  DLOG(logging::Channel::core, "Preparing to give control of Remote Connection to user.");
  give_ctrl_sync.arrive_and_wait();
  user_done_sync.arrive_and_wait();
}

RemoteSettings &
RemoteConnection::settings() noexcept
{
  return remote_settings;
}

MessageType
message_type(std::string_view msg) noexcept
{
  if (msg[0] == '$') {
    msg.remove_prefix(1);
  }
  switch (msg[0]) {
  case 'S':
    [[fallthrough]];
  case 'T':
    [[fallthrough]];
  case 'X':
    [[fallthrough]];
  case 'W':
    [[fallthrough]];
  case 'w':
    [[fallthrough]];
  case 'N':
    return MessageType::StopReply;
  default:
    return MessageType::CommandResponse;
  }
}

qXferResponse
RemoteConnection::append_read_qXfer_response(int timeout, std::string &output) noexcept
{
  while (true) {
    const auto start = socket.next_message(timeout);
    if (!start) {
      return qXferResponse::Timeout;
    }

    switch (start->data) {
    case MessageData::Header: {
      const auto packet_end = socket.find_timeout('#', timeout);
      if (!packet_end) {
        return {};
      }
      std::string_view packet{socket.cbegin() + start->pos + 1, socket.cbegin() + packet_end.value()};
      if (!remote_settings.is_noack && message_type(packet) == MessageType::StopReply) {
        TODO("Implement dispatch of incoming stop reply (that is *not* an async notification event, used in "
             "non-stop) during wait/read/parse for command response");
        write_ack();
      } else {
        const bool done = packet[0] == 'l';
        packet.remove_prefix(1);
        output.append(packet);
        socket.consume_n(packet_end.value() + 3);
        return done ? qXferResponse::Done : qXferResponse::HasMore;
      }
    }
    case MessageData::AsyncHeader: {
      const auto packet_end = socket.find_timeout('#', timeout);
      if (!packet_end) {
        return {};
      }
      const auto packet = std::string_view{socket.cbegin(), socket.cbegin() + packet_end.value()};
      put_pending_notification(packet);
      socket.consume_n(packet_end.value() + 3);
    }
    case MessageData::Ack:
      socket.consume_n(start->pos + 1);
      break;
    case MessageData::Nack: {
      socket.consume_n(start->pos + 1);
      return {};
    } break;
    default:
      break;
    }
  }
}

std::optional<std::string>
RemoteConnection::read_command_response(int timeout, bool expectingStopReply) noexcept
{
  while (true) {
    const auto start = socket.next_message(timeout);
    if (!start) {
      return {};
    }

    switch (start->data) {
    case MessageData::Header: {
      const auto packet_end = socket.find_timeout('#', timeout);
      if (!packet_end) {
        return {};
      }
      const auto packet = std::string_view{socket.cbegin() + start->pos, socket.cbegin() + packet_end.value()};
      if (!remote_settings.is_noack) {
        TODO("we don't support ack-mode, we only support no-ack mode for now.");
      }
      if (message_type(packet) == MessageType::StopReply && !expectingStopReply) {
        put_pending_notification(packet);
        socket.consume_n(packet_end.value() + 3);
        continue;
      } else {
        std::string result{packet};
        socket.consume_n(packet_end.value() + 3);
        return result;
      }
    }
    case MessageData::AsyncHeader: {
      const auto packet_end = socket.find_timeout('#', timeout);
      if (!packet_end) {
        return {};
      }
      const auto packet = std::string_view{socket.cbegin(), socket.cbegin() + packet_end.value()};
      put_pending_notification(packet);
      socket.consume_n(packet_end.value() + 3);
    }
    case MessageData::Ack:
      socket.consume_n(start->pos + 1);
      break;
    case MessageData::Nack: {
      socket.consume_n(start->pos + 1);
      return {};
    } break;
    default:
      break;
    }
  }

  return {};
}

bool
RemoteConnection::execute_command(SocketCommand &cmd, int timeout) noexcept
{
  const auto write_result = socket.write_cmd(cmd.cmd);
  ASSERT(write_result, "Failed to execute command '{}'", cmd.cmd);
  cmd.result = read_command_response(timeout, cmd.response_is_stop_reply);
  return cmd.result.has_value();
}

static constexpr auto OffsetLengthFormatMaxBufSize = "0000000000000000,0000000000000000"sv.size();

static constexpr u32
string_length(const std::string_view &str) noexcept
{
  return str.length();
}

bool
RemoteConnection::execute_command(qXferCommand &cmd, u32 offset, int timeout) noexcept
{
  ASSERT(cmd.fmt[cmd.fmt.size() - 1] == ':' && cmd.fmt[cmd.fmt.size() - 2] != ':',
         "qXferCommand ill-formatted. Should always only end with one ':' even when the command has no annex. We "
         "add the additional ':' in this function: '{}'",
         cmd.fmt);
  if (cmd.response_buffer.capacity() == 0) {
    cmd.response_buffer.reserve(cmd.length);
  }
  const auto annex_sz = cmd.annex.transform(string_length).value_or(0);
  const auto sz = cmd.fmt.size() + annex_sz + 1 + OffsetLengthFormatMaxBufSize;
  char cmd_buf[sz];
  std::memcpy(cmd_buf, cmd.fmt.data(), cmd.fmt.size());
  if (cmd.annex) {
    const auto &annex = cmd.annex.value();
    std::memcpy(cmd_buf + cmd.fmt.size(), annex.data(), annex.size());
  }

  cmd_buf[cmd.fmt.size() + annex_sz] = ':';
  const auto param = cmd_buf + cmd.fmt.size() + annex_sz + 1;

  while (true) {
    auto ptr = format_value(param, offset);
    if (ptr == nullptr) {
      return false;
    }
    *ptr = ',';
    ptr = format_value(++ptr, cmd.length);
    if (ptr == nullptr) {
      return false;
    }
    std::string_view formatted_command{cmd_buf, ptr};
    const auto write_result = socket.write_cmd(formatted_command);
    ASSERT(write_result, "Failed to execute command '{}'", formatted_command);

    switch (append_read_qXfer_response(timeout, cmd.response_buffer)) {
    case qXferResponse::Done:
      return true;
    case qXferResponse::Timeout:
      return false;
    case qXferResponse::HasMore:
      offset += cmd.length;
      break;
    }
  }

  std::unreachable();
}

void
RemoteConnection::parse_supported(std::string_view supported_response) noexcept
{
  DLOG(logging::Channel::remote,
       "Currently we don't really care. We support what we support and expect what we expect until further "
       "notice:\n{}",
       supported_response);
  supported_response.remove_prefix(1);
  const auto supported = utils::split_string(supported_response, ";");
  // This is an absolute requirement set by us.
  bool has_multiprocess = false;
  for (const auto v : supported) {
    if (v.contains("multiprocess")) {
      has_multiprocess = v.back() == '+';
    }
  }

  if (!has_multiprocess) {
    PANIC("Multiprocess syntax extension is an absolute requirement by MDB");
  }
}

bool
RemoteConnection::send_qXfer_command_with_response(qXferCommand &cmd, std::optional<int> timeout) noexcept
{
  tracee_control_mutex.lock();
  ScopedDefer fn{[&]() {
    user_done_sync.arrive_and_wait();
    tracee_control_mutex.unlock();
  }};

  request_control();
  if (!execute_command(cmd, 0, timeout.value_or(0))) {
    return false;
  }

  return true;
}
#define MATCH(var, param, result, expr)                                                                           \
  std::visit(                                                                                                     \
      [&](auto &param) -> result {                                                                                \
        using T = ActualType<decltype(param)>;                                                                    \
        expr                                                                                                      \
      },                                                                                                          \
      var)

utils::Expected<std::vector<std::string>, SendError>
RemoteConnection::send_commands_inorder_failfast(std::vector<std::variant<SocketCommand, qXferCommand>> &&commands,
                                                 std::optional<int> timeout) noexcept
{
  std::vector<std::string> results{};
  results.reserve(commands.size());
  tracee_control_mutex.lock();
  ScopedDefer fn{[&]() {
    user_done_sync.arrive_and_wait();
    tracee_control_mutex.unlock();
  }};

  request_control();
  using MatchResult = bool;
  const auto timeoutValue = timeout.value_or(1000);
  for (auto &&c : commands) {
    // clang-format off
    auto command_result = std::visit(
      Match{[&](SocketCommand &c) noexcept -> MatchResult {
              if (!execute_command(c, timeoutValue)) {
                return false;
              }
              results.emplace_back(std::move(c.result.value()));
              return true;
            },
            [&](qXferCommand &c) noexcept -> MatchResult {
              if (!execute_command(c, 0, timeoutValue)) {
                return false;
              }
              results.emplace_back(std::move(c.response_buffer));
              return true;
            }},
      c);
    // clang-format on
    if (!command_result) {
      return SystemError{0};
    }
  }
  return results;
}

utils::Expected<std::vector<std::string>, SendError>
RemoteConnection::send_inorder_command_chain(std::span<std::string_view> commands,
                                             std::optional<int> timeout) noexcept
{
  tracee_control_mutex.lock();
  ScopedDefer fn{[&]() {
    user_done_sync.arrive_and_wait();
    tracee_control_mutex.unlock();
  }};
  request_control();
  std::vector<std::string> result{};
  result.reserve(commands.size());

  for (const auto c : commands) {
    for (auto retries = 10;; --retries) {
      const auto res = socket.write_cmd(c);
      if (res.is_ok()) {
        break;
      }
      if (retries <= 0) {
        return send_err(res);
      }
    }

    bool ack = !remote_settings.is_noack;
    if (ack) {
      auto ack = socket.wait_for_ack(timeout.value_or(-1));
      if (ack.is_error()) {
        return Timeout{.msg = "Connection timed out waiting for ack"};
      }
      if (!ack->second) {
        return NAck{};
      }
      ASSERT(ack->first == 0, "Expected to see ack (whether ack/nack) at first position");
      socket.consume_n(ack->first + 1);
    }

    const auto response = read_command_response(timeout.value_or(-1), false);
    if (!response) {
      if (socket.size() > 0) {
        return NAck{};
      } else {
        return Timeout{.msg = "Timed out waiting for response to command"};
      }
    }
    result.push_back(std::move(*response));
  }
  return result;
}

void
RemoteConnection::send_interrupt_byte() noexcept
{
  tracee_control_mutex.lock();
  ScopedDefer fn{[&]() {
    user_done_sync.arrive_and_wait();
    tracee_control_mutex.unlock();
  }};

  request_control();
  char Int[1] = {3};
  const auto write_result = socket.write({Int, 1});
  if (!write_result.is_ok()) {
    PANIC("Failed to sent interrupt byte");
  }
}

utils::Expected<std::string, SendError>
RemoteConnection::send_command_with_response(std::string_view command, std::optional<int> timeout) noexcept
{
  // the actual dance of requesting and receiving control, also needs mutually exclusive access.
  // because otherwise, two "control threads", might actually arrive here, and hit the barrier's arrive_and_wait
  // inside of request_control() (instead of 1 control thread and the RemoteConnection thread) and thus "let each
  // other through". Which would be... pretty bad.
  // when this returns, we have control
  tracee_control_mutex.lock();
  ScopedDefer fn{[&]() {
    user_done_sync.arrive_and_wait();
    tracee_control_mutex.unlock();
  }};

  request_control();
  for (auto retries = 10;; --retries) {
    const auto res = socket.write_cmd(command);
    if (res.is_ok()) {
      break;
    }
    if (retries <= 0) {
      return send_err(res);
    }
  }

  bool ack = !remote_settings.is_noack;
  if (ack) {
    auto ack = socket.wait_for_ack(timeout.value_or(-1));
    if (ack.is_error()) {
      return Timeout{.msg = "Connection timed out waiting for ack"};
    }
    if (!ack->second) {
      return NAck{};
    }
    ASSERT(ack->first == 0, "Expected to see ack (whether ack/nack) at first position");
    socket.consume_n(ack->first + 1);
  }

  const auto response = read_command_response(timeout.value_or(-1), false);
  if (!response) {
    if (socket.size() > 0) {
      return NAck{};
    } else {
      return Timeout{.msg = "Timed out waiting for response to command"};
    }
  }
  const auto &ref = response.value();
  if (ref[0] == '$' && ref[1] == 'E') {
    return SendError{SystemError{.syserrno = 0}};
  }

  return std::move(response.value());
}

std::optional<SendError>
RemoteConnection::send_vcont_command(std::string_view command, std::optional<int> timeout) noexcept
{

  // the actual dance of requesting and receiving control, also needs mutually exclusive access.
  // because otherwise, two "control threads", might actually arrive here, and hit the barrier's arrive_and_wait
  // inside of request_control() (instead of 1 control thread and the RemoteConnection thread) and thus "let each
  // other through". Which would be... pretty bad.
  // when this returns, we have control
  tracee_control_mutex.lock();
  ScopedDefer fn{[&]() {
    user_done_sync.arrive_and_wait();
    tracee_control_mutex.unlock();
  }};

  request_control();
  for (auto retries = 10;; --retries) {
    const auto res = socket.write_cmd(command);
    if (res.is_ok()) {
      break;
    }
    if (retries <= 0) {
      return send_err(res);
    }
  }

  if (remote_settings.is_non_stop) {
    const auto response = read_command_response(timeout.value_or(-1), false);
    if (!response) {
      if (socket.size() > 0) {
        return NAck{};
      } else {
        return Timeout{.msg = "Timed out waiting for response to command"};
      }
    }
    if (response != "$OK") {
      return NAck{};
    }
  }
  return {};
}

bool
RemoteConnection::is_connected_to(const std::string &host, int port) noexcept
{
  return this->host == host && this->port == port;
}

static std::mutex InitMutex{};

std::optional<ConnInitError>
RemoteConnection::init_stop_query() noexcept
{
  SocketCommand current_stop_reply{"?"};
  current_stop_reply.response_is_stop_reply = true;
  if (remote_settings.is_non_stop) {
    if (!execute_command(current_stop_reply, 5000)) {
      return ConnInitError{.msg = "Failed to request current stop info"};
    }
    put_pending_notification(current_stop_reply.result.value());
    parse_event_consume_remaining();
  } else {
    if (!execute_command(current_stop_reply, 5000)) {
      return ConnInitError{.msg = "Failed to request current stop info"};
    }
    process_stop_reply_payload(current_stop_reply.result.value(), true);
  }
  return {};
}

void
RemoteConnection::initialize_thread() noexcept
{
  std::lock_guard lock(InitMutex);
  if (!is_initialized) {
    stop_reply_and_event_listener = std::thread{
        [this]() {
          for (;;) {
            PollSetup polling{socket.get_pollcfg().fd, request_command_fd[0],
                              received_async_notif_during_core_ctrl[0]};
            switch (polling.poll(None())) {
            case PollSetup::PolledEvent::None:
              break;
            case PollSetup::PolledEvent::HasIo:
              read_packets();
              break;
            case PollSetup::PolledEvent::AsyncPending:
              parse_event_consume_remaining();
              break;
            case PollSetup::PolledEvent::CmdRequested:
              relinquish_control_to_core();
              break;
            }
          }
        } // namespace gdb
    };
    is_initialized = true;
  }
}

} // namespace gdb