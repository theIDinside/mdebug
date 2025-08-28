/** LICENSE TEMPLATE */
#include "debugger_thread.h"
#include "common.h"
#include <common/panic.h>
#include <csignal>
#include <linux/prctl.h>
#include <stop_token>
#include <sys/prctl.h>

namespace mdb {
DebuggerThread::DebuggerThread(std::string &&name, std::function<void(std::stop_token &)> &&task) noexcept
    : mThreadName(std::move(name)), mWork(std::move(task)), mThread(), mStarted(false)
{
}

DebuggerThread::~DebuggerThread() noexcept
{
  mThread.request_stop();
  if (mThread.joinable()) {
    mThread.join();
  }
}

/* static */
void
DebuggerThread::BlockSigchildMustSucceed() noexcept
{
  // Block SIGCHLD in this thread to handle it only via signalfd
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    perror("sigprocmask");
    PANIC("Blocking SIGCHLD must succeed for MDB to work.");
  }
}

/* static */
std::unique_ptr<DebuggerThread>
DebuggerThread::SpawnDebuggerThread(std::function<void(std::stop_token &)> task) noexcept
{
  auto thread = std::unique_ptr<DebuggerThread>(
    new DebuggerThread{ std::format("mdb-{}", GetNextDebuggerThreadNumber()), std::move(task) });
  thread->Start();
  return thread;
}

/* static */
std::unique_ptr<DebuggerThread>
DebuggerThread::SpawnDebuggerThread(std::string name, std::function<void(std::stop_token &)> task) noexcept
{
  auto thread = std::unique_ptr<DebuggerThread>(new DebuggerThread{ std::move(name), std::move(task) });
  thread->Start();
  return thread;
}

// Start the thread
void
DebuggerThread::Start() noexcept
{
  MDB_ASSERT(mStarted == false, "Thread already started");
  mStarted = true;
  mThread = std::jthread([this](std::stop_token token) {
    BlockSigchildMustSucceed();
    // Be doubly-certain that we have not meddled with SIGCHLD. This is of utmost importance to make signalfd
    // work.
    AssertSigChildIsBlocked();
    auto cStringName = mThreadName.c_str();
    VERIFY(prctl(PR_SET_NAME, cStringName) != -1, "Failed to set DebuggerThread name.");
    mWork(token);
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

bool
DebuggerThread::RequestStop() noexcept
{
  return mThread.request_stop();
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
} // namespace mdb