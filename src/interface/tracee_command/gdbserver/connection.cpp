/** LICENSE TEMPLATE */
// includes
#include "connection.h"
#include "interface/remotegdb/deserialization.h"
#include "shared.h"
#include "stopreply_parser.h"
// mdb workspace includes
#include <array>
#include <common.h>
#include <event_queue.h>
#include <initializer_list>
#include <mdbsys/ptrace.h>
#include <tracer.h>
#include <type_traits>
#include <utils/enumerator.h>
#include <utils/logger.h>
#include <utils/pipes.h>
#include <utils/scope_defer.h>
#include <utils/sync_barrier.h>
#include <utils/util.h>
// system includes
#include <algorithm>
#include <arpa/inet.h>
#include <barrier>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <iterator>
#include <netinet/in.h>
#include <numeric>
#include <sys/socket.h>
#include <sys/user.h>
#include <unistd.h>

namespace mdb::gdb {
using Connection = RemoteConnection::ShrPtr;

std::unordered_map<std::string_view, TraceeStopReason> RemoteConnection::mStopReasonMap{
  { { "watch", TraceeStopReason{ valueOf("watch") } },
    { "rwatch", TraceeStopReason{ valueOf("rwatch") } },
    { "awatch", TraceeStopReason{ valueOf("awatch") } },
    { "syscall_entry", TraceeStopReason{ valueOf("syscall_entry") } },
    { "syscall_return", TraceeStopReason{ valueOf("syscall_return") } },
    { "library", TraceeStopReason{ valueOf("library") } },
    { "replaylog", TraceeStopReason{ valueOf("replaylog") } },
    { "swbreak", TraceeStopReason{ valueOf("swbreak") } },
    { "hwbreak", TraceeStopReason{ valueOf("hwbreak") } },
    { "fork", TraceeStopReason{ valueOf("fork") } },
    { "vfork", TraceeStopReason{ valueOf("vfork") } },
    { "vforkdone", TraceeStopReason{ valueOf("vforkdone") } },
    { "exec", TraceeStopReason{ valueOf("exec") } },
    { "clone", TraceeStopReason{ valueOf("clone") } },
    { "create", TraceeStopReason{ valueOf("create") } } }
};

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
  u64 checksum_acc =
    static_cast<u64>(
      std::accumulate(payload.begin(), payload.end(), i64{ 0 }, [](auto acc, char c) { return acc + i64{ c }; })) %
    256;
  MDB_ASSERT(checksum_acc <= UINT8_MAX, "Checksum incorrect");

  const auto [FirstIndex, SecondIndex] = HexIndices(static_cast<u8>(checksum_acc));
  return std::make_pair(HexDigits[FirstIndex], HexDigits[SecondIndex]);
}

RemoteConnection::RemoteConnection(
  std::string &&host, int port, mdb::ScopedFd &&socket, RemoteSettings settings) noexcept
    : mHost(std::move(host)), mSocket(std::move(socket)), mPort(port), mRemoteSettings(settings)
{
  auto r = ::pipe(mRequestCommandFd);
  if (r == -1) {
    PANIC("Failed to create pipe for command requests");
  }
  r = ::pipe(mReceivedAsyncNotificationDuringCoreControl);
  if (r == -1) {
    PANIC("Failed to create pipe for command requests");
  }
  r = ::pipe(mQuitFd);
  if (r == -1) {
    PANIC("Failed to create pipe for quit request");
  }
}

RemoteConnection::~RemoteConnection() noexcept
{
  close(mRequestCommandFd[0]);
  close(mRequestCommandFd[1]);
  close(mReceivedAsyncNotificationDuringCoreControl[0]);
  close(mReceivedAsyncNotificationDuringCoreControl[1]);
  const auto r = ::write(mQuitFd[1], "+", 1);
  if (r == -1) {
    PANIC("Failed to notify connection thread to shut down");
  }
  mStopReplyAndEventListeners.join();
  close(mQuitFd[0]);
  close(mQuitFd[1]);
}

BufferedSocket::BufferedSocket(mdb::ScopedFd &&fd, u32 reserve_size) noexcept : mCommunicationSocket(std::move(fd))
{
  mBuffer.reserve(reserve_size);
}

bool
BufferedSocket::IsEmpty() const noexcept
{
  return mBuffer.size() - mHead == 0;
}

void
BufferedSocket::Clear() noexcept
{
  mHead = 0;
  mBuffer.clear();
}

bool
BufferedSocket::PollReady(int timeout) const noexcept
{
  pollfd pfd[1];
  pfd[0].fd = mCommunicationSocket;
  pfd[0].events = POLLIN;
  auto ready = poll(pfd, 1, timeout);
  MDB_ASSERT(ready != -1, "poll system call failed on socket fd");
  return (pfd[0].revents & POLLIN) == POLLIN;
}

SendResult
BufferedSocket::Write(std::string_view payload) noexcept
{
  u32 bytes_sent = 0;
  do {
    const auto send_res = send(mCommunicationSocket, payload.data(), payload.size(), 0);
    const auto success = send_res != -1;
    if (!success) {
      DBGLOG(remote, "failed sending {}", payload);
      return SystemError{ .syserrno = errno };
    }
    bytes_sent += send_res;
  } while (bytes_sent < payload.size());

  DBGLOG(remote, "sent: '{}'", payload);
  return SentOk{};
}

SendResult
BufferedSocket::WriteCommand(std::string_view payload) noexcept
{
  u32 sentBytes = 0;
  // TODO(low hanging fruit): This sucks. double writes. Write new container for this specific purpose.
  mOutputBuffer.clear();
  mOutputBuffer.reserve(payload.size() + 4);
  mOutputBuffer.push_back('$');
  u32 acc = 0;
  auto buf_sz = 1u;
  for (; buf_sz < payload.size() + 1; ++buf_sz) {
    char c = payload[buf_sz - 1];
    mOutputBuffer.push_back(c);
    acc += c;
  }
  mOutputBuffer.push_back('#');

  acc = acc % 256;
  u8 csum = acc;
  mOutputBuffer.push_back(HexDigits[(csum & 0xf0) >> 4]);
  mOutputBuffer.push_back(HexDigits[(csum & 0xf)]);
  MDB_ASSERT(mOutputBuffer.size() == payload.size() + 4,
    "Unexpected buffer length: {} == {}",
    mOutputBuffer.size(),
    payload.size() + 4);

  do {
    const auto sendResult = send(mCommunicationSocket, mOutputBuffer.data(), mOutputBuffer.size(), 0);
    const auto success = sendResult != -1;
    if (!success) {
      DBGLOG(remote, "failed sending {}", payload);
      return SystemError{ .syserrno = errno };
    }
    sentBytes += sendResult;
  } while (sentBytes < payload.size());

  DBGLOG(remote, "sent: '{}'", payload);
  return SentOk{};
}

std::optional<std::string>
BufferedSocket::ReadPayload() noexcept
{
  if (mHead == mBuffer.size() || mBuffer.empty()) {
    BufferN(4096);
  }

  auto pos = Find('$').transform([](auto value) { return value + 1; }).value_or(0);
  auto end = Find('#');

  bool size_determined = false;

  while (!size_determined) {
    // URGENT TODO(implement escape parsing, very important)
    if (end) {
      size_determined = true;
    } else {
      const auto r = BufferN(4096);
      if (r == 0) {
        return {};
      }
      end = Find('#');
    }
  }

  std::string result{};
  result.reserve(end.value() - pos);
  std::copy(cbegin() + pos, cbegin() + end.value(), std::back_inserter(result));
  ConsumeN(end.transform([](auto value) { return value + 3; }).value());

  return result;
}

char
BufferedSocket::ReadChar() noexcept
{
  if (mHead == mBuffer.size() || mBuffer.empty()) {
    BufferN(4096);
  }

  const auto result = mBuffer[mHead];
  ConsumeN(1);
  return result;
}

char
BufferedSocket::PeekChar() noexcept
{
  if (Size() == 0) {
    return 0;
  }
  return mBuffer[mHead];
}

u32
BufferedSocket::BufferN(u32 requested) noexcept
{
  MDB_ASSERT(requested <= 4096, "Maximally a page can be buffered on the stack.");
  char buf[4096];
  const bool canRead = PollReady(1);
  if (!canRead) {
    return 0;
  }
  if (const auto res = read(mCommunicationSocket, buf, requested); res != -1) {
    std::copy(buf, buf + res, std::back_inserter(mBuffer));
    return res;
  } else {
    PANIC("Failed to read from socket");
  }
}

u32
BufferedSocket::BufferNWithTimeout(u32 requested, int timeout) noexcept
{
  const bool canRead = PollReady(timeout);
  if (!canRead) {
    return 0;
  } else {
    char buf[4096];
    MDB_ASSERT(requested <= std::size(buf), "Requested size larger than stack buffer.");
    if (const auto res = read(mCommunicationSocket, buf, requested); res != -1) {
      std::copy(buf, buf + res, std::back_inserter(mBuffer));
      return res;
    } else {
      PANIC("Failed to read from socket");
    }
  }
}

bool
BufferedSocket::HasMorePollIfEmpty(int timeout) const noexcept
{
  return Size() > 0 || PollReady(timeout);
}

void
BufferedSocket::ConsumeN(u32 n) noexcept
{
  MDB_ASSERT(
    n + mHead <= mBuffer.size(), "Consuming n={} bytes when there's only {} left", n, mBuffer.size() - mHead);
  if (mHead + n == mBuffer.size()) {
    Clear();
  } else {
    mHead += n;
  }
}

std::optional<MessageElement>
BufferedSocket::NextMessage(int timeout) noexcept
{
  u32 pos = 0;

  if (Size() == 0) {
    if (BufferNWithTimeout(4096, timeout) == 0) {
      return {};
    }
  }
  auto ch = AtUnchecked(pos);
  const auto isPayloadKind = [&](auto ch) { return ch >= 35 && ch <= 45; };

  while (!isPayloadKind(ch)) {
    ++pos;
    if (pos >= Size()) {
      if (BufferNWithTimeout(4096, timeout) == 0) {
        // Means buffer returned 0, due to timeout
        return {};
      }
    } else {
      ch = AtUnchecked(pos);
    }
  }

  return MessageElement{ .pos = pos, .data = static_cast<MessageData>(ch) };
}

std::optional<u32>
BufferedSocket::Find(char c) const noexcept
{
  auto it = std::find(cbegin(), cend(), c);
  if (it == std::end(mBuffer)) {
    return std::nullopt;
  }

  return std::distance(cbegin(), it);
}

std::optional<u32>
BufferedSocket::FindTimeout(char ch, int timeout) noexcept
{
  if (const auto res = Find(ch); res) {
    return res;
  }
  const auto sz = Size();
  if (BufferNWithTimeout(4096, timeout) == 0) {
    return {};
  }
  return FindFrom(ch, sz);
}

std::optional<u32>
BufferedSocket::FindFrom(char c, u32 pos) const noexcept
{
  if (pos >= Size()) {
    return {};
  }

  auto it = std::find(cbegin() + pos, cend(), c);

  if (it == std::end(mBuffer)) {
    return {};
  }

  return std::distance(cbegin(), it);
}

std::optional<std::pair<u32, bool>>
BufferedSocket::FindAck() const noexcept
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

mdb::Expected<std::pair<u32, bool>, Timeout>
BufferedSocket::WaitForAck(int timeout) noexcept
{
  bool noMoreNoAckFound = false;
  while (!noMoreNoAckFound) {
    auto ack = FindAck();
    if (!ack) {
      noMoreNoAckFound = BufferNWithTimeout(4096, timeout) == 0;
    } else {
      return mdb::expected(std::move(*ack));
    }
  }

  return Timeout{ .msg = "Waiting for ACK timed out" };
}

std::optional<char>
BufferedSocket::At(u32 index) const noexcept
{
  if (index >= Size()) {
    return {};
  }

  return *(cbegin() + index);
}

char
BufferedSocket::AtUnchecked(u32 index) const noexcept
{
  return mBuffer[mHead + index];
}

/*static*/
mdb::Expected<Connection, ConnectError>
RemoteConnection::Connect(const std::string &host, int port, std::optional<RemoteSettings> remoteSettings) noexcept
{
  // returns a Expected<ScopedFd, ConnectError>. Transform it into Expected<Connection, ConnectError>
  return mdb::ScopedFd::OpenSocketConnectTo(host, port)
    .and_then<InitError>([&](auto &&socket) -> mdb::Expected<Connection, InitError> {
      std::shared_ptr<RemoteConnection> connection = std::make_shared<RemoteConnection>(
        std::string{ host }, port, std::move(socket), remoteSettings.value_or(RemoteSettings{}));

      return connection;
    });
}

void
RemoteConnection::ConsumePollEvents(int fd) noexcept
{
  MDB_ASSERT(fd == mRequestCommandFd[0] || fd == mReceivedAsyncNotificationDuringCoreControl[0],
    "File descriptor not expected");
  char buf[128];
  const auto bytes_read = ::read(fd, buf, 128);
  if (bytes_read == -1) {
    PANIC("failed to consume poll events from fd")
  }
}

void
RemoteConnection::RequestControl() noexcept
{
  std::lock_guard lock(mTraceeControlMutex);

  auto tries = 0;
  while (::write(mRequestCommandFd[1], "+", 1) == -1 && tries++ < 10) {
  }
  if (tries >= 10) {
    PANIC("failed while requesting control over remote connection socket");
  }
  mGiveControlSynchronization.arrive_and_wait();
}

class PollSetup
{
  int mSocket;
  int mCommandRequest;
  int mAsyncPending;
  int mQuit;
  pollfd mPollFds[4];

public:
  enum class PolledEvent : i8
  {
    None = -1,
    HasIo = 0,
    AsyncPending = 1,
    // A remote controller has requested control and is awaiting `RemoteConnection` to relinquish control of the
    // socket/connection.
    CmdRequested = 2,
    Quit = 3
  };

  PollSetup(int conn_socket, int cmds, int async, int quit_pipe) noexcept
      : mSocket(conn_socket), mCommandRequest(cmds), mAsyncPending(async), mQuit(quit_pipe)
  {
    mPollFds[0] = { mSocket, POLLIN, 0 };
    mPollFds[1] = { mAsyncPending, POLLIN, 0 };
    mPollFds[2] = { mCommandRequest, POLLIN, 0 };
    mPollFds[3] = { mQuit, POLLIN, 0 };
  }

  constexpr auto
  FdCount() noexcept
  {
    return sizeof(mPollFds) / sizeof(pollfd);
  }

  PolledEvent
  Poll(std::optional<int> timeout) noexcept
  {
    static constexpr auto Channels = std::to_array<std::string_view>({ "IO", "Async", "User command request" });
    static constexpr auto Event = std::to_array<PolledEvent>(
      { PolledEvent::HasIo, PolledEvent::AsyncPending, PolledEvent::CmdRequested, PolledEvent::Quit });

    const auto pullEvent = [&](auto pollfd) {
      if (pollfd.fd == mPollFds[0].fd) {
        return true;
      }
      char c;
      return ::read(pollfd.fd, &c, 1) != -1;
    };
    const auto count = ::poll(mPollFds, FdCount(), timeout.value_or(-1));
    if (count == -1 || count == 0) {
      return PolledEvent::None;
    }

    for (auto i = 0; i < 4; ++i) {
      if ((mPollFds[i].revents & POLLIN) == POLLIN) {
        VERIFY(pullEvent(mPollFds[i]), "Expected consumption of one '+' to succeed on: '{}'", Channels[i]);
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
RemoteConnection::WriteAck() noexcept
{
  auto tries = 0;
  while (true && tries < 10) {
    const auto res = mSocket.Write("+").is_ok();
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
RemoteConnection::ReadPackets() noexcept
{
  do {
    if (const auto data = mSocket.ReadPayload(); data) {
      if (!mRemoteSettings.mIsNoAck) {
        WriteAck();
      }
      DBGLOG(remote, "received: {}", *data);
      switch (message_type(*data)) {
      case MessageType::StopReply:
        ProcessStopReplyPayload(*data, false);
        break;
      case MessageType::CommandResponse:
        break;
      }
    }
  } while (mSocket.Size() > 0 || mSocket.HasMorePollIfEmpty(1));
}

std::optional<std::string>
RemoteConnection::TakePending() noexcept
{
  std::optional<std::string> result = std::nullopt;
  result.swap(mPendingNotification);
  return result;
}

/*static*/ std::optional<int>
RemoteConnection::ParseHexDigits(std::string_view input) noexcept
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
RemoteConnection::UpdateKnownThreads(std::span<const GdbThread> threads_) noexcept
{
  mThreads.clear();
  for (const auto gdb_thread : threads_) {
    // pid.pid == process/task leader of pid.tid(s), but it is a task too, not something special.
    mThreads[{ gdb_thread.pid, gdb_thread.pid }].push_back(gdb_thread);
  }
  mThreadsKnown = true;
}

void
RemoteConnection::SetQueryThread(gdb::GdbThread thread) noexcept
{
  if (mSelectedThread != thread) {
    mSelectedThread = thread;
    char buf[64];
    auto end = std::format_to(buf, "Hgp{:x}.{:x}", thread.pid, thread.tid);

    SocketCommand cmd{ { buf, end }, false, false, false, {} };
    if (!ExecuteCommand(cmd, 100)) {
      TODO_FMT("Failed to configure controlling query thread to p{:x}.{:x}", thread.tid, thread.pid);
    }
  }
}

void
RemoteConnection::PutPendingNotification(std::string_view payload) noexcept
{
  MDB_ASSERT(!mPendingNotification.has_value(), "Pending notification has not been consumed");
  mPendingNotification.emplace(payload);
  auto retries = 0;
  while (write(mReceivedAsyncNotificationDuringCoreControl[1], "+", 1) == -1 && retries < 10) {
    ++retries;
  }
  if (retries >= 10) {
    PANIC("Failed to write notification to async notif pipe");
  }
}

std::vector<GdbThread>
ProtocolParseThreads(std::string_view input) noexcept
{
  auto ts = mdb::SplitString(input, ",");
  std::vector<GdbThread> threads{};
  threads.reserve(ts.size());
  for (auto t : ts) {
    auto thread = gdb::GdbThread::MaybeParseThread(t);
    if (thread) {
      threads.push_back(*thread);
    }
  }
  return threads;
}

bool
RemoteConnection::ProcessTaskStopReply(int signal, std::string_view payload, bool isSessionConfig) noexcept
{
  auto params = mdb::SplitString(payload, ";");
  WaitEventParser parser{ *this };
  parser.mControlKindIsAttached = isSessionConfig;
  parser.mSignal = signal;

  static constexpr auto DecodeBufferSize = 64;
  char dec_buf[DecodeBufferSize];

  for (const auto param_str : params) {
    const auto pos = param_str.find(':');
    const auto arg = param_str.substr(0, pos);
    auto val = param_str.substr(pos + 1);
    if (arg == "thread") {
      parser.ParsePidTid(val);
    } else if (arg == "threads") {
      const auto threads = parser.ParseThreadsParameter(val);
      UpdateKnownThreads(threads);
    } else if (arg == "thread-pcs") {
      auto pcs = mdb::SplitString(val, ",");
      DBGLOG(core, "parsing thread-pcs not yet implemented");
    } else if (arg == "core") {
      parser.ParseCore(val);
    } else if (arg == "frametime") {
      parser.ParseEventTime(val);
    } else {
      const auto maybeStopReason = valueOf(arg);
      if (parser.IsStopReason(maybeStopReason)) {
        auto reason = static_cast<TraceeStopReason>(maybeStopReason);
        parser.ParseStopReason(reason, val);
      } else {
        const auto register_number = RemoteConnection::ParseHexDigits(arg);
        auto contents = val;

        auto decoded = gdb::DecodeRunLengthEncToStringView(contents, dec_buf, DecodeBufferSize);
        auto &[no, reg_contents] = parser.mRegisters.emplace_back(register_number.value(), std::vector<u8>{});
        reg_contents.reserve(decoded.length() / 2);
        const auto sz = decoded.size();
        for (auto i = 0u; i < sz; i += 2) {
          reg_contents.push_back(fromhex(decoded[i]) * 16 + fromhex(decoded[i + 1]));
        }
      }
    }
  }

  if (!isSessionConfig) {
    EventSystem::Get().PushDebuggerEvent(parser.NewDebuggerEvent(false));
  } else {
    EventSystem::Get().PushInitEvent(parser.NewDebuggerEvent(true));
  }

  return true;
}

bool
RemoteConnection::ProcessStopReplyPayload(std::string_view receivedPayload, bool isSessionConfig) noexcept
{
  DBGLOG(remote, "Stop reply payload: {}", receivedPayload);
  MDB_ASSERT(!receivedPayload.empty(), "Expected a non-empty payload!");
  if (receivedPayload.front() == '$') {
    receivedPayload.remove_prefix(1);
  }

  StopReplyParser parser{ GetSettings(), receivedPayload };
  const auto kind = parser.StopReplyKind();
  switch (kind) {
  case 'S': {
    TODO("S is a stop reply we don't yet support");
  }
  case 'T': {
    const auto signal = parser.ParseSignal();
    MDB_ASSERT(signal.has_value(), "Expected to have at least the signal data");
    if (!signal) {
      DBGLOG(remote, "Failed to parse signal for T packet: '{}'", receivedPayload);
      return false;
    }
    ProcessTaskStopReply(signal.value(), parser.mParseData, isSessionConfig);
    break;
  }
  case 'W': {
    const auto [target, exit_code] = parser.ParseExited<'W'>();
    if (!exit_code || !target) {
      return false;
    }
    auto *traceEvent = new TraceEvent{};
    TraceEvent::InitProcessExitEvent(traceEvent, target.value(), target.value(), exit_code.value(), {});
    EventSystem::Get().PushDebuggerEvent(traceEvent);
    break;
  }
  case 'X': {
    const auto [target, signal] = parser.ParseExited<'X'>();
    if (!signal || !target) {
      return false;
    }
    TODO("Add Terminated event or make ProcessExit have two variants (i like this better)");
    auto *traceEvent = new TraceEvent{};
    TraceEvent::InitProcessExitEvent(traceEvent, target.value(), target.value(), signal.value(), {});
    EventSystem::Get().PushDebuggerEvent(traceEvent);
    break;
  }
  case 'w': {
    if (const auto res = parser.ParseThreadExited(); res) {
      const auto &[pid, tid, code] = res.value();
      // If we're not non-stop, this will stop the entire process
      const auto processNeedsResuming = !mRemoteSettings.mIsNonStop;
      auto *traceEvent = new TraceEvent{};
      TraceEvent::InitThreadExited(
        traceEvent, { .target = pid, .tid = tid, .sig_or_code = code, .event_time = 0 }, processNeedsResuming, {});
      EventSystem::Get().PushDebuggerEvent(traceEvent);
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
RemoteConnection::ParseEventConsumeRemaining() noexcept
{
  auto pending = TakePending();
  MDB_ASSERT(pending.has_value(), "No pending notification has been read");
  if (!mRemoteSettings.mIsNonStop) {
    auto payload = std::string_view{ pending.value() };
    MDB_ASSERT(payload[0] == '$', "Expected 'synchronous non-stop' stop reply but got {}", payload[0]);
    payload.remove_prefix(1);
    ProcessStopReplyPayload(payload, false);
    // We are done. We are not in non-stop mode, there will be no further rapports.
    return;
  }
  auto payload = std::string_view{ pending.value() };
  MDB_ASSERT(payload[0] == '%', "Expected Notification Header");

  payload.remove_prefix(1);
  MDB_ASSERT(payload.substr(0, 5) == "Stop:", "Only 'Stop' notifications are defined by the protocol as of yet");
  payload.remove_prefix(5);

  const auto sendRes = mSocket.WriteCommand("vStopped");
  if (!sendRes.is_ok()) {
    PANIC(std::format("Failed to acknowledge asynchronous notification: {}", payload));
  }

  ProcessStopReplyPayload(payload, false);

  do {
    auto data = mSocket.ReadPayload();
    if (data == "OK") {
      return;
    }
    ProcessStopReplyPayload(payload, false);
    const auto sendRes = mSocket.Write("vStopped");
    if (!sendRes.is_ok()) {
      PANIC(std::format("Failed to acknowledge asynchronous notification: {}", payload));
    }
  } while (mSocket.HasMorePollIfEmpty(10));
}

void
RemoteConnection::RelinquishControlToCore() noexcept
{
  DBGLOG(core, "Preparing to give control of Remote Connection to user.");
  mGiveControlSynchronization.arrive_and_wait();
  UserDoneSynchronization.arrive_and_wait();
}

RemoteSettings &
RemoteConnection::GetSettings() noexcept
{
  return mRemoteSettings;
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
RemoteConnection::AppendReadQXferResponse(int timeout, std::string &output) noexcept
{
  while (true) {
    const auto start = mSocket.NextMessage(timeout);
    if (!start) {
      return qXferResponse::Timeout;
    }

    switch (start->data) {
    case MessageData::Header: {
      const auto packet_end = mSocket.FindTimeout('#', timeout);
      if (!packet_end) {
        return {};
      }
      std::string_view packet{ mSocket.cbegin() + start->pos + 1, mSocket.cbegin() + packet_end.value() };
      if (!mRemoteSettings.mIsNoAck && message_type(packet) == MessageType::StopReply) {
        TODO("Implement dispatch of incoming stop reply (that is *not* an async notification event, used in "
             "non-stop) during wait/read/parse for command response");
        WriteAck();
      } else {
        const bool done = packet[0] == 'l';
        packet.remove_prefix(1);
        output.append(packet);
        mSocket.ConsumeN(packet_end.value() + 3);
        return done ? qXferResponse::Done : qXferResponse::HasMore;
      }
      NEVER("Should not reach");
    }
    case MessageData::AsyncHeader: {
      const auto packet_end = mSocket.FindTimeout('#', timeout);
      if (!packet_end) {
        return {};
      }
      const auto packet = std::string_view{ mSocket.cbegin(), mSocket.cbegin() + packet_end.value() };
      PutPendingNotification(packet);
      mSocket.ConsumeN(packet_end.value() + 3);
      break;
    }
    case MessageData::Ack:
      mSocket.ConsumeN(start->pos + 1);
      break;
    case MessageData::Nack: {
      mSocket.ConsumeN(start->pos + 1);
      return {};
    } break;
    default:
      break;
    }
  }

  NEVER("Should never reach RemoteConnection::append_read_qXfer_response");
}

std::optional<std::string>
RemoteConnection::ReadCommandResponse(int timeout, bool expectingStopReply) noexcept
{
  while (true) {
    const auto start = mSocket.NextMessage(timeout);
    if (!start) {
      return {};
    }

    switch (start->data) {
    case MessageData::Header: {
      const auto packetEnd = mSocket.FindTimeout('#', timeout);
      if (!packetEnd) {
        return {};
      }
      const auto packet = std::string_view{ mSocket.cbegin() + start->pos, mSocket.cbegin() + packetEnd.value() };
      if (!mRemoteSettings.mIsNoAck) {
        TODO("we don't support ack-mode, we only support no-ack mode for now.");
      }
      if (message_type(packet) == MessageType::StopReply && !expectingStopReply) {
        PutPendingNotification(packet);
        mSocket.ConsumeN(packetEnd.value() + 3);
        continue;
      } else {
        std::string result{ packet };
        mSocket.ConsumeN(packetEnd.value() + 3);
        return result;
      }
    }
    case MessageData::AsyncHeader: {
      const auto packetEnd = mSocket.FindTimeout('#', timeout);
      if (!packetEnd) {
        return {};
      }
      const auto packet = std::string_view{ mSocket.cbegin(), mSocket.cbegin() + packetEnd.value() };
      PutPendingNotification(packet);
      mSocket.ConsumeN(packetEnd.value() + 3);
      break;
    }
    case MessageData::Ack:
      mSocket.ConsumeN(start->pos + 1);
      break;
    case MessageData::Nack: {
      mSocket.ConsumeN(start->pos + 1);
      return {};
    } break;
    default:
      break;
    }
  }

  return {};
}

bool
RemoteConnection::ExecuteCommand(SocketCommand &cmd, int timeout) noexcept
{
  const auto writeResult = mSocket.WriteCommand(cmd.mCommand);
  MDB_ASSERT(writeResult, "Failed to execute command '{}'", cmd.mCommand);
  cmd.mResult = ReadCommandResponse(timeout, cmd.mResponseIsStopReply);
  return cmd.mResult.has_value();
}

static constexpr auto OffsetLengthFormatMaxBufSize = "0000000000000000,0000000000000000"sv.size();

static constexpr u32
string_length(const std::string_view &str) noexcept
{
  return str.length();
}

std::span<const GdbThread>
RemoteConnection::QueryTargetThreads(GdbThread thread, bool forceFlush) noexcept
{
  if (forceFlush) {
    mThreadsKnown = false;
  }
  if (mThreadsKnown) {
    const auto &thrs = mThreads[thread];
    if (!thrs.empty()) {
      return thrs;
    }
  }

  const auto threadsResults = GetRemoteThreads();

  UpdateKnownThreads(threadsResults);

  return mThreads[thread];
}

std::vector<GdbThread>
RemoteConnection::GetRemoteThreads() noexcept
{
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };

  RequestControl();

  std::vector<GdbThread> threads{};

  SocketCommand read_threads{ "qfThreadInfo" };
  if (!ExecuteCommand(read_threads, 1000)) {
    return {};
  }

  std::string_view thr_result{ read_threads.mResult.value() };
  thr_result.remove_prefix("$m"sv.size());
  const auto parsed = ProtocolParseThreads(thr_result);
  threads.reserve(parsed.size());
  for (auto [pid, tid] : parsed) {
    threads.emplace_back(pid, tid);
  }
  for (;;) {
    SocketCommand continue_read_threads{ "qsThreadInfo" };
    if (!ExecuteCommand(continue_read_threads, 1000)) {
      return {};
    }
    std::string_view res{ continue_read_threads.mResult.value() };
    if (res == "$l") {
      break;
    } else {
      res.remove_prefix("$m"sv.size());
      const auto parsed = ProtocolParseThreads(res);
      for (auto [pid, tid] : parsed) {
        threads.emplace_back(pid, tid);
      }
    }
  }
  return threads;
}

bool
RemoteConnection::ExecuteCommand(qXferCommand &cmd, u32 offset, int timeout) noexcept
{
  MDB_ASSERT(cmd.mFmt[cmd.mFmt.size() - 1] == ':' && cmd.mFmt[cmd.mFmt.size() - 2] != ':',
    "qXferCommand ill-formatted. Should always only end with one ':' even when the command has no annex. We "
    "add the additional ':' in this function: '{}'",
    cmd.mFmt);
  if (cmd.mResponseBuffer.capacity() == 0) {
    cmd.mResponseBuffer.reserve(cmd.mLength);
  }
  const auto annexSize = cmd.mAnnex.transform(string_length).value_or(0);
  const auto sz = cmd.mFmt.size() + annexSize + 1 + OffsetLengthFormatMaxBufSize;
  auto buf = mBuffer->TakeSpan(sz);
  std::memcpy(buf.data(), cmd.mFmt.data(), cmd.mFmt.size());
  if (cmd.mAnnex) {
    const auto &annex = cmd.mAnnex.value();
    std::memcpy(buf.data() + cmd.mFmt.size(), annex.data(), annex.size());
  }

  buf[cmd.mFmt.size() + annexSize] = ':';
  const auto param = buf.data() + cmd.mFmt.size() + annexSize + 1;

  while (true) {
    auto ptr = FormatValue(param, offset);
    if (ptr == nullptr) {
      return false;
    }
    *ptr = ',';
    ptr = FormatValue(++ptr, cmd.mLength);
    if (ptr == nullptr) {
      return false;
    }
    std::string_view formattedCommand{ buf.data(), ptr };
    const auto writeResult = mSocket.WriteCommand(formattedCommand);
    MDB_ASSERT(writeResult, "Failed to execute command '{}'", formattedCommand);

    switch (AppendReadQXferResponse(timeout, cmd.mResponseBuffer)) {
    case qXferResponse::Done:
      return true;
    case qXferResponse::Timeout:
      return false;
    case qXferResponse::HasMore:
      offset += cmd.mLength;
      break;
    }
  }

  std::unreachable();
}

void
RemoteConnection::ParseSupported(std::string_view supportedResponse) noexcept
{
  DBGLOG(remote,
    "Currently we don't really care. We support what we support and expect what we expect until further "
    "notice:\n{}",
    supportedResponse);
  supportedResponse.remove_prefix(1);
  const auto supported = mdb::SplitString(supportedResponse, ";");
  // This is an absolute requirement set by us.
  bool hasMultiProcess = false;
  for (const auto v : supported) {
    if (v.contains("multiprocess")) {
      hasMultiProcess = v.back() == '+';
    }
  }

  if (!hasMultiProcess) {
    PANIC("Multiprocess syntax extension is an absolute requirement by MDB");
  }
}

bool
RemoteConnection::SendQXferCommandWithResponse(qXferCommand &cmd, std::optional<int> timeout) noexcept
{
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };

  RequestControl();
  if (!ExecuteCommand(cmd, 0, timeout.value_or(0))) {
    return false;
  }

  return true;
}

mdb::Expected<std::vector<std::string>, SendError>
RemoteConnection::SendCommandsInOrderFailFast(
  std::vector<std::variant<SocketCommand, qXferCommand>> &&commands, std::optional<int> timeout) noexcept
{
  std::vector<std::string> results{};
  results.reserve(commands.size());
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };

  RequestControl();
  using MatchResult = bool;
  const auto timeoutValue = timeout.value_or(1000);
  for (auto &&c : commands) {
    // clang-format off
    auto commandResult = std::visit(
      Match{[&](SocketCommand &c) noexcept -> MatchResult {
              if (!ExecuteCommand(c, timeoutValue)) {
                return false;
              }
              results.emplace_back(std::move(c.mResult.value()));
              return true;
            },
            [&](qXferCommand &c) noexcept -> MatchResult {
              if (!ExecuteCommand(c, 0, timeoutValue)) {
                return false;
              }
              results.emplace_back(std::move(c.mResponseBuffer));
              return true;
            }},
      c);
    // clang-format on
    if (!commandResult) {
      return SendError{ SystemError{ 0 } };
    }
  }
  return results;
}

mdb::Expected<std::vector<std::string>, SendError>
RemoteConnection::SendInOrderCommandChain(
  std::span<std::string_view> commands, std::optional<int> timeout) noexcept
{
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };
  RequestControl();
  std::vector<std::string> result{};
  result.reserve(commands.size());

  for (const auto c : commands) {
    for (auto retries = 10;; --retries) {
      const auto res = mSocket.WriteCommand(c);
      if (res.is_ok()) {
        break;
      }
      if (retries <= 0) {
        return send_err(res);
      }
    }

    bool ack = !mRemoteSettings.mIsNoAck;
    if (ack) {
      auto ack = mSocket.WaitForAck(timeout.value_or(-1));
      if (ack.is_error()) {
        return SendError{ Timeout{ .msg = "Connection timed out waiting for ack" } };
      }
      if (!ack->second) {
        return SendError{ NAck{} };
      }
      MDB_ASSERT(ack->first == 0, "Expected to see ack (whether ack/nack) at first position");
      mSocket.ConsumeN(ack->first + 1);
    }

    std::optional<std::string> response = ReadCommandResponse(timeout.value_or(-1), false);
    if (!response) {
      if (mSocket.Size() > 0) {
        return SendError{ NAck{} };
      } else {
        return SendError{ Timeout{ .msg = "Timed out waiting for response to command" } };
      }
    }
    result.emplace_back(std::move(response).value());
  }
  return result;
}

void
RemoteConnection::SendInterruptByte() noexcept
{
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };

  RequestControl();
  char Int[1] = { 3 };
  const auto writeResult = mSocket.Write({ Int, 1 });
  if (!writeResult.is_ok()) {
    PANIC("Failed to sent interrupt byte");
  }
}

mdb::Expected<std::string, SendError>
RemoteConnection::SendCommandWaitForResponse(
  std::optional<gdb::GdbThread> thread, std::string_view command, std::optional<int> timeout) noexcept
{
  // the actual dance of requesting and receiving control, also needs mutually exclusive access.
  // because otherwise, two "control threads", might actually arrive here, and hit the barrier's arrive_and_wait
  // inside of request_control() (instead of 1 control thread and the RemoteConnection thread) and thus "let each
  // other through". Which would be... pretty bad.
  // when this returns, we have control
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };

  RequestControl();
  if (thread) {
    SetQueryThread(*thread);
  }
  for (auto retries = 10;; --retries) {
    const auto res = mSocket.WriteCommand(command);
    if (res.is_ok()) {
      break;
    }
    if (retries <= 0) {
      return send_err(res);
    }
  }

  bool ack = !mRemoteSettings.mIsNoAck;
  if (ack) {
    auto ack = mSocket.WaitForAck(timeout.value_or(-1));
    if (ack.is_error()) {
      return SendError{ Timeout{ .msg = "Connection timed out waiting for ack" } };
    }
    if (!ack->second) {
      return SendError{ NAck{} };
    }
    MDB_ASSERT(ack->first == 0, "Expected to see ack (whether ack/nack) at first position");
    mSocket.ConsumeN(ack->first + 1);
  }

  auto response = ReadCommandResponse(timeout.value_or(-1), false);
  if (!response) {
    if (mSocket.Size() > 0) {
      return SendError{ NAck{} };
    } else {
      return SendError{ Timeout{ .msg = "Timed out waiting for response to command" } };
    }
  }
  const auto &ref = response.value();
  if (ref[0] == '$' && ref[1] == 'E') {
    return SendError{ SystemError{ .syserrno = 0 } };
  }

  return mdb::expected(std::move(response.value()));
}

std::optional<SendError>
RemoteConnection::SendVContCommand(std::string_view command, std::optional<int> timeout) noexcept
{

  // the actual dance of requesting and receiving control, also needs mutually exclusive access.
  // because otherwise, two "control threads", might actually arrive here, and hit the barrier's arrive_and_wait
  // inside of request_control() (instead of 1 control thread and the RemoteConnection thread) and thus "let each
  // other through". Which would be... pretty bad.
  // when this returns, we have control
  mTraceeControlMutex.lock();
  ScopedDefer fn{ [&]() {
    UserDoneSynchronization.arrive_and_wait();
    mTraceeControlMutex.unlock();
  } };

  RequestControl();
  for (auto retries = 10;; --retries) {
    const auto res = mSocket.WriteCommand(command);
    if (res.is_ok()) {
      break;
    }
    if (retries <= 0) {
      return send_err(res);
    }
  }

  if (mRemoteSettings.mIsNonStop) {
    const auto response = ReadCommandResponse(timeout.value_or(-1), false);
    if (!response) {
      if (mSocket.Size() > 0) {
        return NAck{};
      } else {
        return Timeout{ .msg = "Timed out waiting for response to command" };
      }
    }
    if (response != "$OK") {
      return NAck{};
    }
  }
  return {};
}

bool
RemoteConnection::IsConnectedTo(const std::string &host, int port) noexcept
{
  return this->mHost == host && this->mPort == port;
}

void
RemoteConnection::InvalidateKnownThreads() noexcept
{
  mThreadsKnown = false;
}

static std::mutex InitMutex{};

std::optional<ConnInitError>
RemoteConnection::InitStopQuery() noexcept
{
  SocketCommand currentStopReply{ "?" };
  currentStopReply.mResponseIsStopReply = true;
  if (mRemoteSettings.mIsNonStop) {
    if (!ExecuteCommand(currentStopReply, 5000)) {
      return ConnInitError{ .msg = "Failed to request current stop info" };
    }
    ProcessStopReplyPayload(currentStopReply.mResult.value(), true);
  } else {
    if (!ExecuteCommand(currentStopReply, 5000)) {
      return ConnInitError{ .msg = "Failed to request current stop info" };
    }
    ProcessStopReplyPayload(currentStopReply.mResult.value(), true);
  }
  return {};
}

void
RemoteConnection::InitializeThread() noexcept
{
  std::lock_guard lock(InitMutex);
  if (!mIsInitialized) {
    mStopReplyAndEventListeners = std::thread{
      [this]() {
        for (; mRun;) {
          PollSetup polling{ mSocket.GetPollConfig().fd,
            mRequestCommandFd[0],
            mReceivedAsyncNotificationDuringCoreControl[0],
            mQuitFd[0] };
          switch (polling.Poll(None())) {
          case PollSetup::PolledEvent::None:
            break;
          case PollSetup::PolledEvent::HasIo:
            ReadPackets();
            break;
          case PollSetup::PolledEvent::AsyncPending:
            ParseEventConsumeRemaining();
            break;
          case PollSetup::PolledEvent::CmdRequested:
            RelinquishControlToCore();
            break;
          case PollSetup::PolledEvent::Quit:
            mRun = false;
            break;
          }
        }
      } // namespace gdb
    };
    mIsInitialized = true;
  }
}

/*static*/
GdbThread
GdbThread::parse_thread(std::string_view input) noexcept
{
  auto parse = input;
  if (parse[0] != 'p') {
    Tid tid;
    const auto tidResult = std::from_chars(parse.begin(), parse.end(), tid, 16);
    MDB_ASSERT(tidResult.ec == std::errc(), "failed to parse pid from {}", input);
    return gdb::GdbThread{ 0, tid };
  } else {
    MDB_ASSERT(parse[0] == 'p', "Expected multiprocess thread syntax");
    parse.remove_prefix(1);
    auto sep = parse.find('.');
    if (sep == parse.npos) {
      return {};
    }
    auto first = parse.substr(0, sep);
    parse.remove_prefix(sep + 1);

    Pid pid;
    Tid tid;
    const auto pidResult = std::from_chars(first.begin(), first.end(), pid, 16);
    MDB_ASSERT(pidResult.ec == std::errc(), "failed to parse pid from {}", input);

    const auto tidResult = std::from_chars(parse.begin(), parse.end(), tid, 16);
    MDB_ASSERT(tidResult.ec == std::errc(), "failed to parse pid from {}", input);

    return gdb::GdbThread{ pid, tid };
  }
}

/*static*/
std::optional<GdbThread>
GdbThread::MaybeParseThread(std::string_view input) noexcept
{
  auto parse = input;
  if (parse[0] != 'p') {
    Tid tid;
    const auto tidResult = std::from_chars(parse.begin(), parse.end(), tid, 16);
    if (tidResult.ec != std::errc()) {
      return {};
    }
    return gdb::GdbThread{ 0, tid };
  } else {
    if (parse[0] != 'p') {
      return {};
    }

    parse.remove_prefix(1);
    auto sep = parse.find('.');
    if (sep == parse.npos) {
      return {};
    }
    auto first = parse.substr(0, sep);
    parse.remove_prefix(sep + 1);

    Pid pid;
    Tid tid;
    const auto pidResult = std::from_chars(first.begin(), first.end(), pid, 16);
    const auto tidResult = std::from_chars(parse.begin(), parse.end(), tid, 16);

    if (pidResult.ec != std::errc() || tidResult.ec != std::errc()) {
      return {};
    }

    return gdb::GdbThread{ pid, tid };
  }
}

} // namespace mdb::gdb