/** LICENSE TEMPLATE */
#pragma once
#include "wait_event_parser.h"
#include <barrier>
#include <fmt/core.h>
#include <functional>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/poll.h>
#include <thread>
#include <typedefs.h>
#include <utils/expected.h>
#include <utils/scoped_fd.h>
using MonotonicResource = std::pmr::monotonic_buffer_resource;

namespace mdb {
class BarrierWait;
class BarrierNotify;
} // namespace mdb

namespace mdb::gdb {

// std::string cloned_deserialize_buffer(std::string_view buf) noexcept;

class RemoteSessionConfigurator;

struct RemoteSettings
{
  // Default settings
  bool mCatchSyscalls : 1 {false};
  bool mIsNonStop : 1 {false};
  bool mReportThreadEvents : 1 {true};
  bool mIsNoAck : 1 {true};
  bool mMultiProcessIsConfigured : 1 {true};
  bool mThreadEvents : 1 {true};
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

struct Timeout
{
  std::string_view msg;
};

using SendError = std::variant<SystemError, Timeout, NAck>;

enum class SendResultKind
{
  // We called the system call send() with no errors
  SentOk,
  // `send` system call error
  SystemError,
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
  mdb::ScopedFd mCommunicationSocket;
  std::vector<char> mBuffer{};
  std::vector<char> mOutputBuffer{};
  u32 mHead{0};

  bool IsEmpty() const noexcept;
  void Clear() noexcept;

  mutable std::mutex mWriteMutex{};
  mutable std::mutex mReadMutex{};

public:
  using iterator = typename std::vector<char>::const_iterator;
  using reference = typename std::vector<char>::reference;
  using pointer = typename std::vector<char>::pointer;
  using value_type = typename std::vector<char>::value_type;

  BufferedSocket(mdb::ScopedFd &&fd, u32 reserveCapacity = 4096) noexcept;

  pollfd
  GetPollConfig() const noexcept
  {
    return pollfd{.fd = mCommunicationSocket, .events = POLLIN, .revents = 0};
  }

  constexpr auto
  Size() const noexcept
  {
    // Head is an 0-based index so it's representation in "size" is +1
    return mBuffer.empty() ? 0 : mBuffer.size() - (mHead + 1);
  }

  constexpr bool
  IsOpen() const noexcept
  {
    return true;
  }

  bool PollReady(int timeout) const noexcept;
  SendResult Write(std::string_view payload) noexcept;
  SendResult WriteCommand(std::string_view payload) noexcept;
  char ReadChar() noexcept;
  char PeekChar() noexcept;
  std::optional<std::string> ReadPayload() noexcept;
  bool HasMorePollIfEmpty(int timeout) const noexcept;
  u32 BufferN(u32 requested) noexcept;
  u32 BufferNWithTimeout(u32 requested, int timeout) noexcept;
  void ConsumeN(u32 n) noexcept;
  std::optional<MessageElement> NextMessage(int timeout) noexcept;
  std::optional<u32> Find(char c) const noexcept;
  std::optional<u32> FindTimeout(char ch, int timeout) noexcept;
  std::optional<u32> FindFrom(char c, u32 pos) const noexcept;

  std::optional<std::pair<u32, bool>> FindAck() const noexcept;
  mdb::Expected<std::pair<u32, bool>, Timeout> WaitForAck(int timeout) noexcept;
  std::optional<char> At(u32 index) const noexcept;
  char AtUnchecked(u32 index) const noexcept;

  auto
  cbegin() const noexcept
  {
    return mBuffer.cbegin() + mHead;
  }

  auto
  cend() const noexcept
  {
    return mBuffer.cend();
  }

  auto
  begin() noexcept
  {
    return mBuffer.begin() + mHead;
  }

  auto
  end() noexcept
  {
    return mBuffer.end();
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
  std::barrier<CompletionFnA> &mStart;
  std::barrier<CompletionFnB> &mEnd;
  // If the constructor throws an exception (due to Fn prior_arrive), we need to arrive_and_wait twice in the
  // destructor so that any other thread waiting for this one doesn't become dead locked.
  bool mFirstArriveCompleted{false};

public:
  template <typename Fn>
  explicit ScopeSync(std::barrier<CompletionFnA> &startPoint, std::barrier<CompletionFnA> &endPoint,
                     Fn priorArriveFn) noexcept
      : mStart(startPoint), mEnd(endPoint)
  {
    priorArriveFn();
    mStart.arrive_and_wait();
    mFirstArriveCompleted = true;
  }

  explicit ScopeSync(std::barrier<CompletionFnA> &startPoint, std::barrier<CompletionFnA> &endPoint) noexcept
      : mStart(startPoint), mEnd(endPoint)
  {
    mStart.arrive_and_wait();
    mFirstArriveCompleted = true;
  }

  ~ScopeSync() noexcept
  {
    if (!mFirstArriveCompleted) {
      mStart.arrive_and_wait();
    }
    mEnd.arrive_and_wait();
  }
};

using CommandResult = mdb::Expected<std::string, SendResultKind>;
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
  std::string_view mCommand;
  bool mIsListResponse{false};
  bool mListDone{false};
  bool mResponseIsStopReply{false};
  std::optional<std::string> mResult{std::nullopt};
};

struct ConnInitError
{
  std::string_view msg;
};

using InitError = std::variant<ConnInitError, ConnectError>;

struct qXferCommand
{
  std::string_view mFmt;
  u32 mLength{};
  std::optional<std::string_view> mAnnex{};
  std::string mResponseBuffer{};
};

enum class qXferResponse
{
  Done,
  HasMore,
  Timeout
};

struct GdbThread
{
  Pid pid;
  Tid tid;

  constexpr auto operator<=>(const GdbThread &) const noexcept = default;

  static std::optional<GdbThread> MaybeParseThread(std::string_view input) noexcept;
  static GdbThread parse_thread(std::string_view input) noexcept;
};

}; // namespace mdb::gdb

template <> struct std::hash<mdb::gdb::GdbThread>
{
  using argument_type = mdb::gdb::GdbThread;
  using result_type = u64;

  result_type
  operator()(const argument_type &m) const
  {
    u64 pid{static_cast<u64>(m.pid)};
    u64 tid{static_cast<u64>(m.tid)};

    return pid << 32 | tid;
  }
};

namespace mdb::gdb {

class WriteBuffer
{
  char *mPtr;
  u64 mSize;

  WriteBuffer(char *ptr, u64 size) : mPtr(ptr), mSize(size) {}

public:
  static WriteBuffer *
  Create(u64 pages) noexcept
  {
    auto ptr = (char *)mmap(nullptr, pages * 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    MUST_HOLD(ptr != MAP_FAILED && ptr != nullptr, "mmap failed");
    return new WriteBuffer{ptr, pages * 4096};
  }

  std::span<char>
  TakeSpan(u64 size) noexcept
  {
    if (size > mSize) {
      PANIC("Max size reached");
    }
    return std::span{mPtr, size};
  }
};

class RemoteConnection
{
public:
  using SyncBarrier = std::barrier<std::function<void()>>;
  using ShrPtr = std::shared_ptr<RemoteConnection>;
  friend class GdbRemoteCommander;
  friend class RemoteSessionConfigurator;

private:
  WriteBuffer *mBuffer = WriteBuffer::Create(16);
  std::unordered_map<GdbThread, std::vector<GdbThread>> mThreads;
  std::string mHost;
  BufferedSocket mSocket;
  std::thread mStopReplyAndEventListeners;
  u16 mPort;
  RemoteSettings mRemoteSettings;
  bool mThreadsKnown : 1 {false};
  bool mIsInitialized : 1 {false};
  bool mRemoteConfigured : 1 {false};
  bool mRun : 1 {true};
  gdb::GdbThread mSelectedThread{0, 0};
  std::recursive_mutex mTraceeControlMutex{};

  // When debugger (core) wants control, it will acquire this lock
  // but it will already be in use, whereby we unlock it on the dispatcher thread

  int mRequestCommandFd[2];
  int mReceivedAsyncNotificationDuringCoreControl[2];
  int mQuitFd[2];
  std::barrier<> mGiveControlSynchronization{2};
  std::barrier<> UserDoneSynchronization{2};

  std::optional<std::string> mPendingNotification{std::nullopt};

  void ConsumePollEvents(int fd) noexcept;
  bool ProcessStopReplyPayload(std::string_view payload, bool isSessionConfig) noexcept;
  bool ProcessTaskStopReply(int signal, std::string_view payload, bool isSessionConfig) noexcept;
  void PutPendingNotification(std::string_view payload) noexcept;
  void UpdateKnownThreads(std::span<const GdbThread> threads) noexcept;
  void SetQueryThread(gdb::GdbThread thread) noexcept;

  static std::unordered_map<std::string_view, TraceeStopReason> mStopReasonMap;

public:
  RemoteConnection(std::string &&host, int port, mdb::ScopedFd &&socket, RemoteSettings settings) noexcept;
  ~RemoteConnection() noexcept;

  // Construction and init routines
  static mdb::Expected<ShrPtr, ConnectError> Connect(const std::string &host, int port,
                                                     std::optional<RemoteSettings> remoteSettings) noexcept;

  static std::optional<int> ParseHexDigits(std::string_view input) noexcept;
  std::optional<std::string> TakePending() noexcept;
  std::optional<ConnInitError> InitStopQuery() noexcept;
  void InitializeThread() noexcept;
  void RequestControl() noexcept;
  void ReadPackets() noexcept;
  void WriteAck() noexcept;
  void ParseEventConsumeRemaining() noexcept;
  void RelinquishControlToCore() noexcept;
  RemoteSettings &GetSettings() noexcept;
  void ParseSupported(std::string_view supported) noexcept;

  // Fill the comms buffer and read it and parse it's contents. If we come across stop replies (whether we are in
  // non-stop or not),
  std::optional<std::string> ReadCommandResponse(int timeout, bool expectingStopReply) noexcept;
  // Returns {true} if done, {false} if not done and {} if we timeout
  qXferResponse AppendReadQXferResponse(int timeout, std::string &output) noexcept;
  std::optional<std::pmr::string> ReadCommandResponse(MonotonicResource &arena, int timeout) noexcept;

  // Blocking call for `timeout` ms
  mdb::Expected<std::string, SendError> SendCommandWaitForResponse(std::optional<gdb::GdbThread> thread,
                                                                   std::string_view command,
                                                                   std::optional<int> timeout) noexcept;

  void SendInterruptByte() noexcept;

  mdb::Expected<std::vector<std::string>, SendError> SendInOrderCommandChain(std::span<std::string_view> commands,
                                                                             std::optional<int> timeout) noexcept;

  // Make these private. These should not be called as they place *ultimate* responsibility on the caller that it
  // has done the acquire + synchronize dance.
  bool ExecuteCommand(SocketCommand &cmd, int timeout) noexcept;
  bool ExecuteCommand(qXferCommand &cmd, u32 offset, int timeout) noexcept;
  std::vector<GdbThread> GetRemoteThreads() noexcept;
  std::span<const GdbThread> QueryTargetThreads(GdbThread thread, bool forceFlush) noexcept;

  mdb::Expected<std::vector<std::string>, SendError>
  SendCommandsInOrderFailFast(std::vector<std::variant<SocketCommand, qXferCommand>> &&commands,
                              std::optional<int> timeout) noexcept;

  // For some bozo reason, vCont commands don't reply with `OK` - that only happens when in noack mode. Dumbest
  // fucking "protocol" in the history of the universe.
  std::optional<SendError> SendVContCommand(std::string_view command, std::optional<int> timeout) noexcept;

  bool SendQXferCommandWithResponse(qXferCommand &cmd, std::optional<int> timeout) noexcept;
  bool IsConnectedTo(const std::string &host, int port) noexcept;
  void InvalidateKnownThreads() noexcept;
};

std::vector<GdbThread> ProtocolParseThreads(std::string_view input) noexcept;

} // namespace mdb::gdb