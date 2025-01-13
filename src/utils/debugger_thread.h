/** LICENSE TEMPLATE */
#pragma once
#include <functional>
#include <thread>

class DebuggerThread
{
  explicit DebuggerThread(std::function<void()> &&task) noexcept;

public:
  using OwnedPtr = std::unique_ptr<DebuggerThread>;

  ~DebuggerThread() noexcept;
  /// Create a debugger thread
  static std::unique_ptr<DebuggerThread> SpawnDebuggerThread(std::function<void()> task) noexcept;

  /// Start the thread.
  void Start() noexcept;
  /// Join the thread.
  void Join() noexcept;
  /// Check if the thread is joinable.
  bool IsJoinable() const noexcept;

  /// Asserts that SIGCHILD as a signal is blocked before thread is started
  /// and after it's started to make sure that it never gets allowed.
  /// This is required by the WAIT system.
  static void AssertSigChildIsBlocked() noexcept;

private:
  std::function<void()> mWork; // The task to run in the thread
  std::thread mThread;         // The underlying std::thread
  bool mStarted;
};