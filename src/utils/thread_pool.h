/** LICENSE TEMPLATE */
#pragma once
#include "utils/debugger_thread.h"
#include "worker_task.h"
#include <numeric>
#include <queue>
#include <typedefs.h>
#include <vector>

namespace utils {

// clang-format off
template <typename ContainerT>
concept Containerish = requires(ContainerT c) {
  c.size();
  c.begin();
  c.end();
};
// clang-format on

class ThreadPool
{
public:
  ThreadPool() noexcept;
  ~ThreadPool();
  void Init(u32 pool_size) noexcept;
  u32 WorkerCount() const noexcept;
  static ThreadPool *GetGlobalPool() noexcept;
  void PostTask(Task *task) noexcept;
  void PostTasks(std::span<Task *> tasks) noexcept;
  std::vector<Task *> ShutdownTasks() noexcept;
  void WorkerLoop(std::stop_token &stop_token) noexcept;

  static void
  ShutdownGlobalPool() noexcept
  {
    delete sGlobalThreadPool;
  }

private:
  static ThreadPool *sGlobalThreadPool;
  std::vector<std::unique_ptr<DebuggerThread>> mThreadPool;
  std::queue<Task *> mTaskQueue;
  std::queue<std::unique_ptr<TaskGroup>> mTaskGroup;
  std::mutex mTaskMutex;
  std::condition_variable mTaskConditionVariable;
};
} // namespace utils