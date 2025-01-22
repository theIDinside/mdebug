/** LICENSE TEMPLATE */
#pragma once
#include <functional>
#include <thread>

class DebuggerThread
{
  static int
  GetNextDebuggerThreadNumber()
  {
    static int i = 0;
    return i++;
  }

  std::string mThreadName;
  explicit DebuggerThread(std::string &&name, std::function<void(std::stop_token &)> &&task) noexcept;

public:
  using OwnedPtr = std::unique_ptr<DebuggerThread>;

  ~DebuggerThread() noexcept;
  /// Create a debugger thread
  static std::unique_ptr<DebuggerThread> SpawnDebuggerThread(std::function<void(std::stop_token &)> task) noexcept;
  static std::unique_ptr<DebuggerThread> SpawnDebuggerThread(std::string threadName,
                                                             std::function<void(std::stop_token &)> task) noexcept;

  /// Start the thread.
  void Start() noexcept;
  /// Join the thread.
  void Join() noexcept;
  /// Check if the thread is joinable.
  bool IsJoinable() const noexcept;
  /// Request jthread to stop
  bool RequestStop() noexcept;

  /// Asserts that SIGCHILD as a signal is blocked before thread is started
  /// and after it's started to make sure that it never gets allowed.
  /// This is required by the WAIT system.
  static void AssertSigChildIsBlocked() noexcept;

private:
  std::function<void(std::stop_token &tok)> mWork; // The task to run in the thread
  std::jthread mThread;                            // The underlying std::thread
  bool mStarted;
};