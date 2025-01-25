/** LICENSE TEMPLATE */
#include "thread_pool.h"
#include <stop_token>
#include <sys/prctl.h>
#include <utils/signals.h>

namespace utils {

/*static*/ ThreadPool *
ThreadPool::GetGlobalPool() noexcept
{
  return sGlobalThreadPool;
}

void
ThreadPool::PostTask(Task *task) noexcept
{
  std::lock_guard lock(mTaskMutex);
  mTaskQueue.push(task);
  mTaskConditionVariable.notify_one();
}

void
ThreadPool::PostTasks(std::span<Task *> tasks) noexcept
{
  std::lock_guard lock(mTaskMutex);
  for (auto t : tasks) {
    mTaskQueue.push(t);
  }
  mTaskConditionVariable.notify_all();
}

ThreadPool::ThreadPool() noexcept
    : mThreadPool(), mTaskQueue(), mTaskGroup(), mTaskMutex(), mTaskConditionVariable()
{
}

ThreadPool::~ThreadPool()
{
  auto tasks = ShutdownTasks();
  for (auto &t : mThreadPool) {
    t->RequestStop();
  }
  for (auto t : tasks) {
    PostTask(t);
  }
}

void
ThreadPool::Init(u32 pool_size) noexcept
{
  mThreadPool.reserve(pool_size);
  for (auto i = 0u; i < pool_size; ++i) {
    mThreadPool.emplace_back(DebuggerThread::SpawnDebuggerThread(
      fmt::format("PoolWorker-{}", i), [&](std::stop_token &token) { WorkerLoop(token); }));
  }
}

u32
ThreadPool::WorkerCount() const noexcept
{
  return mThreadPool.size();
}

std::vector<Task *>
ThreadPool::ShutdownTasks() noexcept
{
  std::vector<Task *> res;
  const auto sz = WorkerCount();
  res.reserve(sz);
  for (auto i = 0u; i < sz; ++i) {
    res.push_back(new NoOp{});
  }
  return res;
}

void
ThreadPool::WorkerLoop(std::stop_token &stop_token) noexcept
{
  while (true && !stop_token.stop_requested()) {
    Task *job = nullptr;
    {
      std::unique_lock lock(mTaskMutex);
      while (mTaskQueue.empty()) {
        mTaskConditionVariable.wait(lock);
      }
      job = mTaskQueue.front();
      mTaskQueue.pop();
    }
    ASSERT(job != nullptr, "Failed to retrieve work from task queue");
    job->Execute();
    delete job;
  }
}
} // namespace utils