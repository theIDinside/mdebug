/** Binary Logging Library - Implementation */
#include <binlog/logger.h>
#include <chrono>

namespace binlog {

// Static member initialization
thread_local BinaryLogger::ThreadLocalBuffer BinaryLogger::sThreadBuffer{};
std::atomic<u64> BinaryLogger::sSequenceCounter{ 1 };

BinaryLogger::BinaryLogger(const Config &config)
{
  // Open binary log file
  mLogFile = std::fstream{ config.logFilePath, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc };

  if (!mLogFile.is_open()) {
    mLogFile.open(config.logFilePath, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
  }

  if (!mLogFile.is_open()) {
    throw std::runtime_error("Failed to open binary log file");
  }

  // Spawn async flush thread
  mFlushThread = std::make_unique<std::thread>([this]() { FlushThreadMain(); });
}

void
BinaryLogger::FlushThreadLocal() noexcept
{
  if (sThreadBuffer.size == 0) {
    return;
  }

  // Copy thread-local buffer to temporary vector
  std::vector<u8> buffer(sThreadBuffer.buffer, sThreadBuffer.buffer + sThreadBuffer.size);

  // Queue for async write
  {
    std::lock_guard lock(mFlushMutex);
    mFlushQueue.emplace_back(std::move(buffer));
  }

  // Notify flush thread
  mFlushCV.notify_one();

  // Reset thread-local buffer
  sThreadBuffer.Clear();
}

void
BinaryLogger::WriteBufferedMessages() noexcept
{
  std::vector<std::vector<u8>> localQueue;

  // Swap out the flush queue
  {
    std::lock_guard lock(mFlushMutex);
    localQueue.swap(mFlushQueue);
  }

  // Write all buffered messages to the unified log file
  for (auto &buffer : localQueue) {
    if (mLogFile.is_open()) {
      mLogFile.write(reinterpret_cast<const char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
      mLogFile.flush();
    }
  }
}

void
BinaryLogger::FlushThreadMain() noexcept
{
  while (!mShutdown) {
    // Wait for notification or timeout
    {
      std::unique_lock lock(mFlushMutex);
      mFlushCV.wait_for(
        lock, std::chrono::milliseconds(100), [this] { return !mFlushQueue.empty() || mShutdown; });
    }

    if (!mFlushQueue.empty()) {
      WriteBufferedMessages();
    }
  }

  // Final flush on shutdown
  WriteBufferedMessages();
}

void
BinaryLogger::Shutdown() noexcept
{
  if (mShutdown) {
    return;
  }

  mShutdown = true;

  // Notify flush thread to wake up
  mFlushCV.notify_one();

  // Wait for flush thread to finish
  if (mFlushThread && mFlushThread->joinable()) {
    mFlushThread->join();
    mFlushThread.reset();
  }

  // Close the log file
  if (mLogFile.is_open()) {
    mLogFile.flush();
    mLogFile.close();
  }
}

BinaryLogger::~BinaryLogger() noexcept { Shutdown(); }

} // namespace binlog
