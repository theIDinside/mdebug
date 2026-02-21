/** LICENSE TEMPLATE */
#include "thread_pool.h"
#include <stop_token>
#include <sys/prctl.h>
#include <utils/signals.h>

namespace mdb {
/*static*/ ThreadPool *
ThreadPool::GetGlobalPool() noexcept
{
  return sGlobalThreadPool;
}

void
ThreadPool::PostTask(std::shared_ptr<TaskBase> task) noexcept
{
  std::lock_guard lock(mTaskMutex);
  mTaskQueue.emplace(std::move(task));
  mTaskConditionVariable.notify_one();
}

void
ThreadPool::PostTasks(std::span<std::shared_ptr<TaskBase>> tasks) noexcept
{
  std::lock_guard lock(mTaskMutex);
  mTaskQueue.push_range(tasks);
  mTaskConditionVariable.notify_all();
}

ThreadPool::ThreadPool() noexcept = default;

ThreadPool::~ThreadPool()
{

  for (auto &t : mThreadPool) {
    t->RequestStop();
  }

  auto tasks = ShutdownTasks();
  PostTasks(tasks);

  for (auto &t : mThreadPool) {
    if (t->IsJoinable()) {
      t->Join();
    }
  }
}

void
ThreadPool::Init(u32 pool_size) noexcept
{
  mThreadPool.reserve(pool_size);
  for (auto i = 0U; i < pool_size; ++i) {
    mThreadPool.emplace_back(DebuggerThread::SpawnDebuggerThread(
      std::format("PoolWorker-{}", i), [&](std::stop_token &token) { WorkerLoop(token); }));
  }
}

u32
ThreadPool::WorkerCount() const noexcept
{
  return mThreadPool.size();
}

std::vector<std::shared_ptr<TaskBase>>
ThreadPool::ShutdownTasks() const noexcept
{
  std::vector<std::shared_ptr<TaskBase>> res;
  const auto sz = WorkerCount();
  res.reserve(sz);
  for (auto i = 0U; i < sz; ++i) {
    res.emplace_back(std::make_shared<NoOp>());
  }
  return res;
}

std::shared_ptr<TaskBase>
ThreadPool::TakeFront()
{
  auto result = std::move(mTaskQueue.front());
  mTaskQueue.pop();
  return result;
}

void
ThreadPool::WorkerLoop(std::stop_token &stop_token) noexcept
{
  while (!stop_token.stop_requested()) {
    std::shared_ptr<TaskBase> job = nullptr;
    {
      std::unique_lock lock(mTaskMutex);
      while (mTaskQueue.empty()) {
        mTaskConditionVariable.wait(lock);
      }
      while (!mTaskQueue.empty()) {
        job = TakeFront();
        // Task has not been cancelled, execute it
        if (!job->IsCancelled()) {
          break;
        }
      }
    }
    MDB_ASSERT(job != nullptr, "Failed to retrieve work from task queue");
    job->Execute();
  }
}
} // namespace mdb