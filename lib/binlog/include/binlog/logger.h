/** Binary Logging Library - High-Performance Binary Logger */
#pragma once

// binlog
#include <binlog/encoding.h>

// std
#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <source_location>
#include <string_view>
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
  static constexpr u32 sChannelSize = 1;
  static constexpr u32 sFormatIdSize = 4;
  static constexpr u32 sTimestampSize = 8;
  static constexpr u32 sSequenceIdSize = 8;
  static constexpr u32 sThreadIdSize = 4;
  static constexpr u32 sFileNamePrefixSize = 4;
  static constexpr u32 sLineNumberSize = 4;
  static constexpr u32 sArgCountSize = 4;

private:
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
  static constexpr u32
  HeaderSize(std::string_view fileName) noexcept
  {
    return sChannelSize + sFormatIdSize + sTimestampSize + sSequenceIdSize + sThreadIdSize + sFileNamePrefixSize +
           sLineNumberSize + fileName.size() + sArgCountSize;
  }

  /**
   * Calculate the exact size needed for a single argument.
   * Format: [1 byte type tag][data]
   * - Bool: 1 byte
   * - Int/Float/Enum/Pointer: 8 bytes
   * - String: [4 byte length][N bytes data]
   */
  template <typename Arg>
  static constexpr u32
  CalculateArgSize(const Arg &arg) noexcept
  {
    constexpr ArgType type = GetArgType<Arg>();

    if constexpr (type == ArgType::Bool) {
      return 1 + 1; // type tag + bool value
    } else if constexpr (type == ArgType::SignedInt || type == ArgType::UnsignedInt || type == ArgType::Float ||
                         type == ArgType::Enum || type == ArgType::Pointer) {
      return 1 + 8; // type tag + 64-bit value
    } else if constexpr (type == ArgType::String) {
      if constexpr (HasValueMethod<Arg> && !DirectlySerializable<Arg>) {
        std::string_view str = arg.value();
        return 1 + 4 + static_cast<u32>(str.size()); // type tag + length prefix + string data
      } else {
        std::string_view str = arg;
        return 1 + 4 + static_cast<u32>(str.size()); // type tag + length prefix + string data
      }
    } else {
      std::terminate();
      return 0;
    }
  }

public:
  template <typename... Args>
  static constexpr u32
  CalculateRequiredPayloadSize(std::string_view fileName, const Args &...args)
  {
    u32 headerSize = HeaderSize(fileName);
    u32 argsPaylodSize = (CalculateArgSize(args) + ... + 0); // +0 handles empty Args

    return headerSize + argsPaylodSize;
  }

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
  // Encodes argValue directly into buffer. Performs no unwrapping of T.
  // NOTE: Does NOT write the type tag - that's done by EncodeArg
  template <ArgType type, typename T>
  constexpr static void
  EncodeValue(u8 *buffer, u32 &offset, const T &argValue)
  {
    if constexpr (type == ArgType::Bool) {
      offset += BinaryWriter::WriteByte(buffer + offset, argValue ? 1 : 0);
    } else if constexpr (type == ArgType::SignedInt) {
      const i64 value = static_cast<i64>(argValue);
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::UnsignedInt) {
      const u64 value = static_cast<u64>(argValue);
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::Float) {
      const double value = static_cast<double>(argValue);
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::Enum) {
      const u64 value = static_cast<u64>(static_cast<std::underlying_type_t<T>>(argValue));
      offset += BinaryWriter::Write64(buffer + offset, value);
    } else if constexpr (type == ArgType::String) {
      static_assert(std::convertible_to<T, std::string_view>, "Requires conversion from T to std::string_view");
      std::string_view str = argValue;
      offset += BinaryWriter::WriteString(buffer + offset, str);
    } else if constexpr (type == ArgType::Pointer) {
      const u64 addr = reinterpret_cast<u64>(argValue);
      offset += BinaryWriter::Write64(buffer + offset, addr);
    }
  }

  template <typename T>
  static void
  EncodeArg(u8 *buffer, u32 &offset, const T &arg) noexcept
  {
    constexpr ArgType type = GetArgType<T>();
    constexpr u8 typeValue = static_cast<u8>(type);

    // Debug: Print type information at compile time
    static_assert(typeValue > 0 && typeValue <= 7, "Invalid ArgType detected at compile time");

    offset += BinaryWriter::WriteByte(buffer + offset, typeValue);

    if constexpr (HasValueMethod<T> && !DirectlySerializable<T>) {
      return EncodeValue<type>(buffer, offset, arg.value());
    } else {
      return EncodeValue<type>(buffer, offset, arg);
    }
  }
};

/**
 * Configuration for the binary logger.
 */
struct BinaryLoggerConfig
{
  std::filesystem::path logFilePath; // Path to binary log file
  u32 bufferSize{ 1024 * 1024 * 4 }; // 4 MB. The larger, the less times blocking will happen.
};

struct Alloc
{
  u8 *mPtr;
  u32 mOffset;
  u32 mSize;
};

/**
 * High-performance binary logging system.
 * Uses lock-free ring buffers with atomic allocation to avoid contention.
 * Call sites allocate space directly and write into the returned pointer.
 * Only when a swap buffer is full, do we acquire a lock.
 * Keep your buffers at a size where that rarely happens and
 * we should be theoretically fast.
 */
template <size_t BufferCount> class BinaryLogger
{

  struct SwapBuffer
  {
    std::unique_ptr<u8[]> mStorage;
    u32 mBufferSize;
    std::atomic<u32> mOffset{ 0 };
    bool mSwapped{ false };
    // Whether or not this buffer is clean and available to be used in a swap. mAvailable means it's either in-use,
    // or awaiting to be swapped (then mSwapped will be true, as well)
    bool mAvailable{ true };
    u32 mBytesFlushed{ 0 };

    SwapBuffer() = default;
    explicit SwapBuffer(u32 bufferSize) noexcept
        : mStorage(std::make_unique<u8[]>(bufferSize)), mBufferSize(bufferSize)
    {
    }

    SwapBuffer(SwapBuffer &) = delete;
    SwapBuffer(const SwapBuffer &) = delete;
    SwapBuffer &operator=(const SwapBuffer &) = delete;

    SwapBuffer(SwapBuffer &&) = default;
    SwapBuffer &operator=(SwapBuffer &&) = default;

    Alloc
    AtomicAcquireSpace(u32 size) noexcept
    {
      mAvailable = false;
      const u32 bestCaseOldOffset = mOffset.fetch_add(size, std::memory_order_acq_rel);
      return Alloc{ .mPtr = mStorage.get() + bestCaseOldOffset, .mOffset = bestCaseOldOffset, .mSize = size };
    }

    void
    SwapAndReclaim(const Alloc &alloc)
    {
      mOffset.store(alloc.mOffset);
      mSwapped = true;
    }

    void
    Clear() noexcept
    {
      mOffset.store(0);
      mSwapped = false;
      mAvailable = true;
      mBytesFlushed = 0;
    }

    constexpr u8 *
    Get(u32 offset) noexcept
    {
      return mStorage.get() + offset;
    }

    constexpr bool
    AllocIsValid(const Alloc &alloc)
    {
      return alloc.mOffset + alloc.mSize <= mBufferSize;
    }
  };

  // This allocate system does *not* maintain ordering when there's a buffer swap that needs to happen
  // But, given that the decoder can shuffle around in the right order (and it's expected to only have a few out
  // of order at any time) that's a good enough tradeoff. A caller will try to allocate `size` bytes for itself,
  // if there is enough space in the current buffer
  //
  u8 *
  AllocateSpace(u32 size) noexcept
  {
    if (size > mBufferSize) {
      std::terminate();
    }

    while (true) {
      // Get current buffer index
      const u32 bestCaseBufferIndex = mCurrentBufferIdx.load(std::memory_order_acquire);

      SwapBuffer &firstAttemptBuffer = mBuffers[bestCaseBufferIndex];

      // Atomically bump the offset and get the old value.
      // The old value is where "this message" would start writing into.
      const Alloc firstAttemptAlloc = firstAttemptBuffer.AtomicAcquireSpace(size);

      // Check if we fit in this buffer
      if (firstAttemptBuffer.AllocIsValid(firstAttemptAlloc)) {
        // Success! We got space in the current buffer
        return firstAttemptAlloc.mPtr;
      }

      // at this point, we've moved the head of the buffer, beyond it's capacity. No more messages can go in to
      // this buffer, and as such, every caller will begin blocking here. Amortized cost, and rare with larger
      // buffer sizes.

      // Enter blocking CS.
      std::unique_lock lock(mBufferSelectionMutex);
      // Since we've set the pointer, beyond the buffer size, it will need to get set "back" to the previous
      // position. It will do so, _after_ it has updated the "current buffer index" to ensure no race issues.

      // By doing the same calculations again, we're checking if someone else also was blocked before us, and did
      // the update steps needed.
      {
        const u32 bufferIdx = mCurrentBufferIdx.load(std::memory_order_acquire);
        if (bufferIdx != bestCaseBufferIndex) {
          SwapBuffer &buffer = mBuffers[bufferIdx];
          const auto alloc = buffer.AtomicAcquireSpace(size);
          if (!buffer.AllocIsValid(alloc)) {
            // This really should *never* happen. It means all log callers got blocked
            // and while waiting, *another* buffer got filled and swapped
            buffer.SwapAndReclaim(alloc);
            const u32 nextBufferIdx = (bufferIdx + 1) % BufferCount;
            UpdateCurrentBufferIndex(nextBufferIdx);
            return nullptr;
          }
          return alloc.mPtr;
        }
      }

      // We overflowed this buffer, need to move to the next one
      const u32 nextBufferIdx = (bestCaseBufferIndex + 1) % BufferCount;
      SwapBuffer &newBuffer = mBuffers[nextBufferIdx];

      if (!newBuffer.mAvailable) {
        std::terminate();
      }

      // We take the pointer into the soon-to-swapped-in-buffer _before_ we update the current index,
      // because that means no one can accidentally sneak in and get this position (before the mutex)
      // when we update the current index, the next user will see start+some size offset in the new buffer.
      // regardless if that user is before the mutex lock or in the CS after it
      const Alloc newAlloc = newBuffer.AtomicAcquireSpace(size);

      // Now, before we return the pointer into the new buffer, set back the position of the old buffer, so that
      // the logger can know how much *actual* space it needs to write from that swap buffer. This is safe
      // because we're in a CS protected by the mutex, and no one can write to this buffer anymore.
      firstAttemptBuffer.SwapAndReclaim(firstAttemptAlloc);

      UpdateCurrentBufferIndex(nextBufferIdx);

      // TODO: Mark the old buffer (bufferIdx) as ready to flush
      return newAlloc.mPtr;
    }
  }

  void
  UpdateCurrentBufferIndex(u32 newBufferIndex)
  {
    mCurrentBufferIdx.store(newBufferIndex, std::memory_order_release);
    mCurrentToFlush.push_back(newBufferIndex);
    mFlushCV.notify_one();
  }

  // Returns the index of the current flushable buffer. Note: The buffer may actually not have any flushable
  // data, it's just the one buffer that next will contain data to be flushed, when it has some
  u32
  GetFlushableCurrent() const
  {
    return mCurrentToFlush.front();
  }

  void
  WriteRaw(const u8 *buffer, u32 bytes)
  {
    mLogFile.write((const char *)buffer, bytes);
  }

  bool
  CanWrite() const
  {
  }

  void
  WriteBufferedMessages() noexcept
  {
    // TODO: Implement flushing logic
    SwapBuffer &buffer = mBuffers[GetFlushableCurrent()];
    auto lastOffset = buffer.mOffset.load(std::memory_order_acquire);
    if (buffer.mBytesFlushed < lastOffset && lastOffset < mBufferSize) {
      const auto bytesToWrite = lastOffset - buffer.mBytesFlushed;
      WriteRaw(buffer.Get(buffer.mBytesFlushed), bytesToWrite);
      buffer.mBytesFlushed += bytesToWrite;
    } else if (lastOffset > mBufferSize) {
      // Means we entered here, when lastOffset was set beyond size. Spin another round in the wait,
      // as the offset will get reset back to the last actual position of the end of the last message
      return;
    }

    // The buffer has been swapped out, and we've flushed the entire buffer. Erase it from flush list and move on
    // to the next.
    if (buffer.mSwapped && buffer.mBytesFlushed == lastOffset) {
      mCurrentToFlush.erase(mCurrentToFlush.begin());
      buffer.Clear();
    }
  }

public:
  BinaryLogger(const BinaryLogger &) = delete;
  BinaryLogger &operator=(const BinaryLogger &) = delete;

  explicit BinaryLogger(const BinaryLoggerConfig &config) noexcept : mBufferSize(config.bufferSize)
  {
    for (auto i = 0; i < BufferCount; ++i) {
      std::construct_at(mBuffers.data() + i, mBufferSize);
      // mBuffers[i] = SwapBuffer{ std::make_unique<u8[]>(mBufferSize), 0, false, 0 };
    }

    mCurrentToFlush.reserve(BufferCount);
    mCurrentToFlush.push_back(0);

    // TODO: Use better than fstream
    mLogFile =
      std::fstream{ config.logFilePath, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc };

    if (!mLogFile.is_open()) {
      mLogFile.open(config.logFilePath, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
    }

    if (!mLogFile.is_open()) {
      std::terminate();
    }
  }

  ~BinaryLogger() noexcept { Shutdown(); }

  void
  MainWaitFlushOnce(std::stop_token token) noexcept
  {
    std::unique_lock lock(mFlushMutex);
    mFlushCV.wait_for(lock, std::chrono::milliseconds(100), [&token] { return token.stop_requested(); });

    WriteBufferedMessages();
  }

  void
  Shutdown() noexcept
  {
    if (mShutdown) {
      return;
    }

    mShutdown = true;

    // Notify flush thread to wake up
    mFlushCV.notify_one();

    // Wait for flush thread to finish
    WriteBufferedMessages();

    // Close the log file
    if (mLogFile.is_open()) {
      mLogFile.flush();
      mLogFile.close();
    }
  }

  template <typename... Args>
  void
  Log(u8 channel, u32 formatId, const std::source_location &loc, const Args &...args) noexcept
  {
    if (mShutdown) {
      return;
    }

    const u64 timestampUs =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
    const u64 seqNum = sSequenceCounter.fetch_add(1, std::memory_order_relaxed);
    const u32 threadId = static_cast<u32>(std::hash<std::thread::id>{}(std::this_thread::get_id()));

    std::string_view fileName = loc.file_name();
    u32 totalSize = BinaryLogEncoder::CalculateRequiredPayloadSize(loc.file_name(), args...);
    // Allocate space from the logger
    int tries = 0;
    u8 *buffer = AllocateSpace(totalSize);
    while (!buffer && tries < 10) {
      ++tries;
      u8 *buffer = AllocateSpace(totalSize);
    }

    if (buffer == nullptr) {
      // Allocation failed (shouldn't happen in normal operation)
      return;
    }

    BinaryLogEncoder::EncodeMessage(
      buffer, channel, formatId, timestampUs, seqNum, threadId, fileName, loc.line(), args...);
  }

private:
  // Configuration
  u32 mBufferSize;

  // Ring buffers
  std::array<SwapBuffer, BufferCount> mBuffers;
  std::atomic<u32> mCurrentBufferIdx{ 0 };
  std::vector<u32> mCurrentToFlush;

  // Shutdown and I/O
  bool mShutdown{ false };
  std::mutex mFlushMutex;
  std::mutex mBufferSelectionMutex;
  std::condition_variable mFlushCV;
  std::fstream mLogFile;

  std::atomic<u64> sSequenceCounter = 1;
};

} // namespace binlog
