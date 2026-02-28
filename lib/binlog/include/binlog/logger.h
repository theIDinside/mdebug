/** Binary Logging Library - High-Performance Binary Logger */
#pragma once
#include <atomic>
#include <binlog/encoding.h>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <source_location>
#include <thread>
#include <vector>

namespace binlog {

// Type-dependent false (works even before C++17)
template <class...> struct always_false_t : std::false_type
{
};

template <class... Ts> inline constexpr bool always_false = always_false_t<Ts...>::value;

// Also useful for non-type template params (optional)
template <auto...> struct always_false_value : std::false_type
{
};

template <auto... Vs> inline constexpr bool always_false_v = always_false_value<Vs...>::value;

/**
 * Binary log message encoder.
 * Handles type-safe serialization of log arguments to binary format.
 */
class BinaryLogEncoder
{
public:
  /**
   * Encodes a log message with arguments into the provided buffer.
   * Returns the number of bytes written.
   *
   * Message format (all fixed-size except strings):
   * [1 byte channel]
   * [4 bytes format_id]
   * [8 bytes timestamp_us]
   * [8 bytes sequence_number]
   * [4 bytes thread_id]
   * [4 bytes file_name_length][N bytes filename]
   * [4 bytes line_number]
   * [1 byte arg_count]
   * [arguments...]
   */
  template <typename... Args>
  static u32
  EncodeMessage(u8 *buffer,
    u8 channel,
    u32 formatId,
    u64 timestampUs,
    u64 sequenceNumber,
    u32 threadId,
    std::string_view fileName,
    u32 lineNumber,
    const Args &...args) noexcept
  {
    u32 offset = 0;

    // Write header
    offset += BinaryWriter::WriteByte(buffer + offset, channel);
    offset += BinaryWriter::Write(buffer + offset, formatId);
    offset += BinaryWriter::Write64(buffer + offset, timestampUs);
    offset += BinaryWriter::Write64(buffer + offset, sequenceNumber);
    offset += BinaryWriter::Write(buffer + offset, threadId);
    offset += BinaryWriter::WriteString(buffer + offset, fileName);
    offset += BinaryWriter::Write(buffer + offset, lineNumber);
    offset += BinaryWriter::Write(buffer + offset, static_cast<u32>(sizeof...(Args)));

    // Write arguments
    (EncodeArg(buffer, offset, args), ...);

    return offset;
  }

private:
  template <typename T>
  static void
  EncodeArg(u8 *buffer, u32 &offset, const T &arg) noexcept
  {
    constexpr ArgType type = GetArgType<T>();
    constexpr u8 typeValue = static_cast<u8>(type);

    // Debug: Print type information at compile time
    static_assert(typeValue > 0 && typeValue <= 7, "Invalid ArgType detected at compile time");

    // NOTE: buffer already points to the correct write position!
    // EncodeMessage calls us with (buffer + offset, offset, arg)
    offset += BinaryWriter::WriteByte(buffer + offset, typeValue);

    // Unwrap wrapper types (e.g., std::optional, custom wrappers with .value())
    const auto &unwrapped = UnwrapValue(arg);
    using UnwrappedType = std::remove_cvref_t<decltype(unwrapped)>;

    if constexpr (type == ArgType::Bool) {
      offset += BinaryWriter::WriteByte(buffer + offset, unwrapped ? 1 : 0);
    } else if constexpr (type == ArgType::SignedInt) {
      const i64 value = static_cast<i64>(unwrapped);
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::UnsignedInt) {
      const u64 value = static_cast<u64>(unwrapped);
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::Float) {
      const double value = static_cast<double>(unwrapped);
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::Enum) {
      const u64 value = static_cast<u64>(static_cast<std::underlying_type_t<UnwrappedType>>(unwrapped));
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::String) {
      std::string_view str;
      if constexpr (std::is_same_v<UnwrappedType, std::string_view>) {
        str = unwrapped;
      } else if constexpr (std::is_same_v<UnwrappedType, const char *> || std::is_same_v<UnwrappedType, char *>) {
        // Check for null pointer
        if (unwrapped != nullptr) {
          str = std::string_view(unwrapped);
        } else {
          str = std::string_view("<null>");
        }
      } else if constexpr (std::is_same_v<UnwrappedType, std::string>) {
        str = std::string_view(unwrapped);
      } else if constexpr (std::is_convertible_v<UnwrappedType, std::string_view>) {
        str = static_cast<std::string_view>(unwrapped);
      }
      offset += BinaryWriter::WriteString(buffer + offset, str);
    } else if constexpr (type == ArgType::Pointer) {
      const u64 addr = reinterpret_cast<u64>(unwrapped);
      offset += BinaryWriter::Write64(buffer + offset, addr);
    }
  }
};

/**
 * High-performance binary logging system.
 * Uses thread-local buffers to avoid contention and async flushing to minimize I/O overhead.
 */
class BinaryLogger
{
public:
  BinaryLogger(const BinaryLogger &) = delete;
  BinaryLogger &operator=(const BinaryLogger &) = delete;

  /**
   * Thread-local buffer for collecting log messages before flushing.
   */
  struct alignas(64) ThreadLocalBuffer
  {
    static constexpr u32 CAPACITY = 65536; // 64KB
    u8 buffer[CAPACITY];
    u32 size{ 0 };
    u32 messageCount{ 0 };

    [[nodiscard]] constexpr bool
    ShouldFlush() const noexcept
    {
      return size > (CAPACITY * 7 / 8) || messageCount > 100;
    }

    constexpr void
    Clear() noexcept
    {
      size = 0;
      messageCount = 0;
    }

    [[nodiscard]] constexpr u32
    Remaining() const noexcept
    {
      return CAPACITY - size;
    }
  };

  /**
   * Configuration for the binary logger.
   */
  struct Config
  {
    std::filesystem::path logFilePath; // Path to binary log file
  };

  BinaryLogger(const Config &config);
  ~BinaryLogger() noexcept;

  /**
   * Main logging entry point.
   */
  template <typename... Args>
  void
  Log(u8 channel, u32 formatId, const std::source_location &loc, const Args &...args) noexcept
  {
    if (mShutdown) {
      return;
    }

    // Estimate message size
    constexpr u32 HEADER_SIZE = 1 + 4 + 8 + 8 + 4 + 256 + 4 + 1;
    constexpr u32 ARG_SIZE = (9 + 256) * sizeof...(Args);
    constexpr u32 estimatedSize = HEADER_SIZE + ARG_SIZE;

    if (sThreadBuffer.Remaining() < estimatedSize) {
      FlushThreadLocal();
    }

    const u64 timestampUs =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
    const u64 seqNum = sSequenceCounter.fetch_add(1, std::memory_order_relaxed);
    const u32 threadId = static_cast<u32>(std::hash<std::thread::id>{}(std::this_thread::get_id()));

    const u32 bytesWritten = BinaryLogEncoder::EncodeMessage(sThreadBuffer.buffer + sThreadBuffer.size,
      channel,
      formatId,
      timestampUs,
      seqNum,
      threadId,
      loc.file_name(),
      loc.line(),
      args...);

    sThreadBuffer.size += bytesWritten;
    ++sThreadBuffer.messageCount;

    if (sThreadBuffer.ShouldFlush()) {
      FlushThreadLocal();
    }
  }

  void Shutdown() noexcept;

private:
  bool mShutdown{ false };
  std::mutex mFlushMutex{};
  std::condition_variable mFlushCV{};
  std::unique_ptr<std::thread> mFlushThread{ nullptr };
  std::fstream mLogFile{};
  std::vector<std::vector<u8>> mFlushQueue{};

  static thread_local ThreadLocalBuffer sThreadBuffer;
  static std::atomic<u64> sSequenceCounter;

  void FlushThreadLocal() noexcept;
  void WriteBufferedMessages() noexcept;
  void FlushThreadMain() noexcept;
};

} // namespace binlog
