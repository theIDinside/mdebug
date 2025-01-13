/** LICENSE TEMPLATE */
#include "debugger_thread.h"
#include "common.h"
#include <csignal>
DebuggerThread::DebuggerThread(std::function<void()> &&task) noexcept
    : mWork(std::move(task)), mThread(), mStarted(false)
{
}

DebuggerThread::~DebuggerThread() noexcept
{
  if (mThread.joinable()) {
    mThread.join();
  }
}

/* static */
std::unique_ptr<DebuggerThread>
DebuggerThread::SpawnDebuggerThread(std::function<void()> task) noexcept
{
  auto thread = std::unique_ptr<DebuggerThread>(new DebuggerThread{std::move(task)});
  thread->Start();
  return thread;
}

// Start the thread
void
DebuggerThread::Start() noexcept
{
  ASSERT(mStarted == false, "Thread already started");
  AssertSigChildIsBlocked();
  mStarted = true;
  mThread = std::thread([this]() {
    // Be doubly-certain that we have not meddled with SIGCHLD. This is of utmost importance to make signalfd
    // work.
    AssertSigChildIsBlocked();
    mWork();
  });
}

// Join the thread
void
DebuggerThread::Join() noexcept
{
  if (mThread.joinable()) {
    mThread.join();
  }
}

// Check if the thread is joinable
bool
DebuggerThread::IsJoinable() const noexcept
{
  return mThread.joinable();
}

/* static */ void
DebuggerThread::AssertSigChildIsBlocked() noexcept
{
  sigset_t current_mask;
  if (pthread_sigmask(SIG_SETMASK, nullptr, &current_mask) != 0) {
    PANIC("Failed to get signal mask for thread.");
  }

  if (!sigismember(&current_mask, SIGCHLD)) {
    PANIC("SIGCHLD is not blocked for thread.");
  }
}