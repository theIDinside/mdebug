#pragma once
#include "interface/remotegdb/target_description.h"
#include "utils/macros.h"
#include "wait_event_parser.h"
#include <barrier>
#include <bit>
#include <charconv>
#include <condition_variable>
#include <filesystem>
#include <fmt/core.h>
#include <functional>
#include <list>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <sys/poll.h>
#include <thread>
#include <typedefs.h>
#include <utils/expected.h>
#include <utils/scoped_fd.h>
using MonotonicResource = std::pmr::monotonic_buffer_resource;

namespace utils {
class BarrierWait;
class BarrierNotify;
} // namespace utils

namespace gdb {

class RemoteSessionConfigurator;

struct RemoteSettings
{
  // Default settings
  bool catch_syscalls : 1 {false};
  bool is_non_stop : 1 {false};
  bool report_thread_events : 1 {true};
  bool is_noack : 1 {true};
  bool multiprocess_configured : 1 {true};
  bool thread_events : 1 {true};
};

static constexpr char HexDigits[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

enum class MessageType
{
  StopReply,
  CommandResponse
};

constexpr std::pair<u8, u8>
HexIndices(u8 checksum) noexcept
{
  static constexpr auto FirstDigitMask = 0b1111'0000;
  static constexpr auto SecondDigitMask = 0b0000'1111;
  const auto FirstIndex = (checksum & FirstDigitMask) >> 4;
  const auto SecondIndex = (checksum & SecondDigitMask);
  ASSERT(FirstIndex < 16 && SecondIndex < 16, "Index out of bounds");
  return std::make_pair(FirstIndex, SecondIndex);
}

std::pair<char, char> checksum(std::string_view payload) noexcept;

enum class SocketResultKind : u8
{
  DataUnavailable,
  Ok,
  Error,
};

struct SocketResult
{
  i32 value;
  SocketResultKind success;

  constexpr u32
  bytes_read() const noexcept
  {
    ASSERT(success == SocketResultKind::Ok, "Socket operation failed");
    const auto res = static_cast<u32>(value);
    return res;
  }

  constexpr i32
  error_number() const noexcept
  {
    ASSERT(success == SocketResultKind::Error, "Socket operation succeeded");
    return value;
  }

  constexpr bool
  is_ok() const noexcept
  {
    return success == SocketResultKind::Ok;
  }

  inline static constexpr SocketResult
  Ok(i32 bytes) noexcept
  {
    return SocketResult{.value = bytes, .success = SocketResultKind::Ok};
  }

  inline static constexpr SocketResult
  Error(i32 sys_errno) noexcept
  {
    return SocketResult{.value = sys_errno, .success = SocketResultKind::Error};
  }

  inline static constexpr SocketResult
  Timeout() noexcept
  {
    return SocketResult{.value = 0, .success = SocketResultKind::DataUnavailable};
  }
};

struct SentOk
{
};

struct RemoteReceived
{
};

struct NAck
{
};

struct SystemError
{
  int syserrno;
};

struct NonsensePayload
{
  std::string_view payload;
};

struct Timeout
{
  std::string_view msg;
};

using SendError = std::variant<SystemError, NonsensePayload, Timeout, NAck>;

enum class SendResultKind
{
  // We called the system call send() with no errors
  SentOk,
  // `send` system call error
  SystemError,
  // When no sense can be made of what has been read from the data read from the socket to the remote
  NonsensePayload,
  // Waiting for response timed out
  ResponseTimeout,
  // Remote responded with a NACK
  NotAck
};

struct SendResult
{
  SendResult() = delete;
  SendResult(const SendResult &) noexcept = default;
  // because saying SendResult res = other_res is not how this type is supposed to work.
  // this type is explicitly intended to report results from operations via returns.
  // I'm not sure this type will hold any (real) data, or complex data, and instead think this
  // type is supposed to signal *where* to look for the error data by what kind it is, since we don't have
  // algebraic data types, like in Rust, for instance.
  SendResult &operator=(const SendResult &) = delete;

  SendResult(SentOk ok) noexcept : kind(SendResultKind::SentOk), ok(ok) {}
  SendResult(SystemError error) noexcept : kind(SendResultKind::SystemError), error(error) {}
  SendResult(NonsensePayload error) noexcept : kind(SendResultKind::NonsensePayload), gbg(std::move(error)) {}
  SendResult(Timeout timeout) noexcept : kind(SendResultKind::ResponseTimeout), timeout(timeout) {}
  SendResult(NAck nack) noexcept : kind(SendResultKind::NotAck), nack(nack) {}
  SendResult(const SocketResult &socket_result) noexcept
  {
    switch (socket_result.success) {
    case SocketResultKind::DataUnavailable:
      kind = SendResultKind::ResponseTimeout;
      break;
    case SocketResultKind::Ok:
      kind = SendResultKind::SentOk;
      break;
    case SocketResultKind::Error:
      kind = SendResultKind::SystemError;
      error = SystemError{.syserrno = socket_result.error_number()};
      break;
    }
  }

  operator bool() const noexcept { return is_ok(); }

  SendResultKind kind;
  union
  {
    SentOk ok;
    RemoteReceived remote_ok;
    SystemError error;
    NonsensePayload gbg;
    Timeout timeout;
    NAck nack;
  };

  constexpr bool
  is_ok() const noexcept
  {
    return kind == SendResultKind::SentOk;
  }

  constexpr SystemError
  system_error() const noexcept
  {
    ASSERT(kind == SendResultKind::SystemError, "Send Result is not a SystemError kind");
    return error;
  }

  constexpr NAck
  not_acknowledged() const noexcept
  {
    ASSERT(kind == SendResultKind::NotAck, "Send Result is not a NAck kind");
    return nack;
  }

  constexpr Timeout
  timed_out() const noexcept
  {
    ASSERT(kind == SendResultKind::ResponseTimeout, "Send Result is not a timeout");
    return timeout;
  }
};

enum class CommandReply
{
  Ok,
  Payload,
};

using SequenceId = int;

template <size_t N> struct CommandSerializationBuffer
{
  char buf[N];
  u32 size;

  template <typename... Args>
  void
  write_packet(fmt::format_string<Args...> fmt, Args &&...args)
  {
    buf[0] = '$';
    auto ptr = fmt::format_to(buf + 1, fmt, args...);
    size = ptr - buf;
    buf[size] = '#';
    auto [a, b] = gdb::checksum({buf, buf + size});
    buf[size + 1] = a;
    buf[size + 2] = b;
    size += 2;
  }

  constexpr auto
  contents() const noexcept
  {
    return std::string_view{buf, buf + size};
  }

  auto
  clear() noexcept
  {
    size = 0;
  }
};

struct Notification
{
};

struct Error
{
  union
  {
    Timeout timeout;
  };
};

enum class MessageData : char
{
  Checksum = '#',
  Header = '$',
  AsyncHeader = '%',
  Ack = '+',
  Nack = '-',
  Escape = '}',
};

struct MessageElement
{
  u32 pos;
  MessageData data;
};

// A socket that tries to buffer reads. Writes are sent immediately.
class BufferedSocket
{
  utils::ScopedFd fd_socket;
  std::vector<char> buffer{};
  u32 head{0};

  bool empty() const noexcept;
  void clear() noexcept;

  mutable std::mutex write_mutex{};
  mutable std::mutex read_mutex{};

public:
  using iterator = typename std::vector<char>::const_iterator;
  using reference = typename std::vector<char>::reference;
  using pointer = typename std::vector<char>::pointer;
  using value_type = typename std::vector<char>::value_type;

  BufferedSocket(utils::ScopedFd &&fd, u32 reserve_size = 4096) noexcept;

  pollfd
  get_pollcfg() const noexcept
  {
    return pollfd{.fd = fd_socket, .events = POLLIN, .revents = 0};
  }

  constexpr auto
  size() const noexcept
  {
    // Head is an 0-based index so it's representation in "size" is +1
    return buffer.empty() ? 0 : buffer.size() - (head + 1);
  }

  constexpr bool
  is_open() const noexcept
  {
    return true;
  }

  bool ready(int timeout) const noexcept;
  SendResult write(std::string_view payload) noexcept;
  SendResult write_cmd(std::string_view payload) noexcept;
  char read_char() noexcept;
  char peek_char() noexcept;
  std::optional<std::string> read_payload() noexcept;
  bool has_more_poll_if_empty(int timeout) const noexcept;
  u32 buffer_n(u32 requested) noexcept;
  u32 buffer_n_timeout(u32 requested, int timeout) noexcept;
  void consume_n(u32 n) noexcept;
  std::optional<MessageElement> next_message(int timeout) noexcept;
  std::optional<u32> find(char c) const noexcept;
  std::optional<u32> find_timeout(char ch, int timeout) noexcept;
  std::optional<u32> find_from(char c, u32 pos) const noexcept;

  std::optional<std::pair<u32, bool>> find_ack() const noexcept;
  utils::Expected<std::pair<u32, bool>, Timeout> wait_for_ack(int timeout) noexcept;
  std::optional<char> at(u32 index) const noexcept;
  char at_unchecked(u32 index) const noexcept;

  auto
  cbegin() const noexcept
  {
    return buffer.cbegin() + head;
  }

  auto
  cend() const noexcept
  {
    return buffer.cend();
  }

  auto
  begin() noexcept
  {
    return buffer.begin() + head;
  }

  auto
  end() noexcept
  {
    return buffer.end();
  }
};

struct RemotePacketOk
{
};

enum class RemotePacketError
{
  Ok,
  SendFailed,
  ReplyTimeout,
  AckMissing,
  Disconnected,
  ExclusiveAccessFailed,
};

/// Scope sync calls arrive_and_wait on a synchronization point (barrier) twice, once on entry (construction) and
/// once on exit (destruction)
template <typename CompletionFnA = std::function<void()>, typename CompletionFnB = std::function<void()>>
class ScopeSync
{
  std::barrier<CompletionFnA> &start;
  std::barrier<CompletionFnB> &end;
  // If the constructor throws an exception (due to Fn prior_arrive), we need to arrive_and_wait twice in the
  // destructor so that any other thread waiting for this one doesn't become dead locked.
  bool first_arrive_completed{false};

public:
  template <typename Fn>
  explicit ScopeSync(std::barrier<CompletionFnA> &start_point, std::barrier<CompletionFnA> &end_point,
                     Fn prior_arrive) noexcept
      : start(start_point), end(end_point)
  {
    prior_arrive();
    start.arrive_and_wait();
    first_arrive_completed = true;
  }

  explicit ScopeSync(std::barrier<CompletionFnA> &start_point, std::barrier<CompletionFnA> &end_point) noexcept
      : start(start_point), end(end_point)
  {
    start.arrive_and_wait();
    first_arrive_completed = true;
  }

  ~ScopeSync() noexcept
  {
    if (!first_arrive_completed) {
      start.arrive_and_wait();
    }
    end.arrive_and_wait();
  }
};

using CommandResult = utils::Expected<std::string, SendResultKind>;
class RemoteConnection;

MessageType message_type(std::string_view msg) noexcept;

class StringBuilder
{
  char *payload;
  u32 size;
  u32 capacity;

  void
  realloc(u32 size) noexcept
  {
    (void)size;
  }

public:
  explicit StringBuilder(u32 cap) noexcept : size(0), capacity(cap) { payload = new char[cap]; }

  ~StringBuilder() noexcept { delete[] payload; }

  static std::unique_ptr<StringBuilder>
  create(u32 cap) noexcept
  {
    return std::make_unique<StringBuilder>(cap);
  }

  void
  update_head(u32 bytes_read) noexcept
  {
    size += bytes_read;
  }

  template <typename ReadFn>
  bool
  read_from(u32 bytes_read, bool allow_realloc, ReadFn fn) noexcept
  {
    if (size + bytes_read > capacity) {
      if (!allow_realloc) {
        return false;
      } else {
        realloc(size + bytes_read + capacity);
      }
    }
    const auto actual_read = fn(bytes_read);
    update_head(actual_read);
    return true;
  }
};

struct SocketCommand
{
  std::string_view cmd;
  bool is_list_response{false};
  bool list_done{false};
  bool response_is_stop_reply{false};
  std::optional<std::string> result{std::nullopt};
};

struct ConnInitError
{
  std::string_view msg;
};

using InitError = std::variant<ConnInitError, ConnectError>;

struct qXferCommand
{
  std::string_view fmt;
  u32 length{};
  std::optional<std::string_view> annex{};
  std::string response_buffer{};
};

enum class qXferResponse
{
  Done,
  HasMore,
  Timeout
};

class RemoteConnection
{
public:
  using SyncBarrier = std::barrier<std::function<void()>>;
  using ShrPtr = std::shared_ptr<RemoteConnection>;
  friend class GdbRemoteCommander;
  friend class RemoteSessionConfigurator;

private:
  std::string host;
  int port;
  BufferedSocket socket;
  std::thread stop_reply_and_event_listener;
  RemoteSettings remote_settings;
  bool is_initialized{false};
  bool remote_configured{false};
  std::recursive_mutex tracee_control_mutex{};
  // Architectures controlled via this remote connection
  std::unordered_map<Pid, std::shared_ptr<gdb::ArchictectureInfo>> archs{};

  // When debugger (core) wants control, it will acquire this lock
  // but it will already be in use, whereby we unlock it on the dispatcher thread

  int request_command_fd[2];
  int received_async_notif_during_core_ctrl[2];
  std::barrier<> give_ctrl_sync{2};
  std::barrier<> user_done_sync{2};

  std::optional<std::string> pending_notification{std::nullopt};

  void consume_poll_events(int fd) noexcept;
  bool process_stop_reply_payload(std::string_view payload, bool is_session_config) noexcept;
  bool process_task_received_signal_extended(int signal, std::string_view payload,
                                             bool is_session_config) noexcept;
  void put_pending_notification(std::string_view payload) noexcept;

  static std::unordered_map<std::string_view, TraceeStopReason> StopReasonMap;

public:
  RemoteConnection(std::string &&host, int port, utils::ScopedFd &&socket, RemoteSettings settings) noexcept;
  ~RemoteConnection() noexcept;

  // Construction and init routines
  static utils::Expected<ShrPtr, ConnectError> connect(const std::string &host, int port,
                                                       std::optional<RemoteSettings> remote_settings) noexcept;

  static std::optional<int> parse_hexdigits(std::string_view input) noexcept;
  std::optional<std::string> take_pending() noexcept;
  std::optional<ConnInitError> init_stop_query() noexcept;
  void initialize_thread() noexcept;
  void request_control() noexcept;
  void read_packets() noexcept;
  void write_ack() noexcept;
  void parse_event_consume_remaining() noexcept;
  void relinquish_control_to_core() noexcept;
  RemoteSettings &settings() noexcept;
  void parse_supported(std::string_view supported) noexcept;

  // Fill the comms buffer and read it and parse it's contents. If we come across stop replies (whether we are in
  // non-stop or not),
  std::optional<std::string> read_command_response(int timeout, bool expectingStopReply) noexcept;
  // Returns {true} if done, {false} if not done and {} if we timeout
  qXferResponse append_read_qXfer_response(int timeout, std::string &output) noexcept;
  std::optional<std::pmr::string> read_command_response(MonotonicResource &arena, int timeout) noexcept;

  // Blocking call for `timeout` ms
  utils::Expected<std::string, SendError> send_command_with_response(std::string_view command,
                                                                     std::optional<int> timeout) noexcept;

  utils::Expected<std::vector<std::string>, SendError>
  send_inorder_command_chain(std::span<std::string_view> commands, std::optional<int> timeout) noexcept;

  // Make these private. These should not be called as they place *ultimate* responsibility on the caller that it
  // has done the acquire + synchronize dance.
  bool execute_command(SocketCommand &cmd, int timeout) noexcept;
  bool execute_command(qXferCommand &cmd, u32 offset, int timeout) noexcept;

  utils::Expected<std::vector<std::string>, SendError>
  send_commands_inorder_failfast(std::vector<std::variant<SocketCommand, qXferCommand>> &&commands,
                                 std::optional<int> timeout) noexcept;

  // For some bozo reason, vCont commands don't reply with `OK` - that only happens when in noack mode. Dumbest
  // fucking "protocol" in the history of the universe.
  std::optional<SendError> send_vcont_command(std::string_view command, std::optional<int> timeout) noexcept;

  bool send_qXfer_command_with_response(qXferCommand &cmd, std::optional<int> timeout) noexcept;
  bool is_connected_to(const std::string &host, int port) noexcept;
};

} // namespace gdb