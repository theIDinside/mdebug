/** LICENSE TEMPLATE */
#pragma once
#include "utils/debugger_thread.h"
#include "worker_task.h"
#include <common/typedefs.h>
#include <queue>
#include <vector>

namespace mdb {
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
  void PostTask(std::shared_ptr<TaskBase> task) noexcept;
  void PostTasks(std::span<std::shared_ptr<TaskBase>> tasks) noexcept;
  std::vector<std::shared_ptr<TaskBase>> ShutdownTasks() const noexcept;
  void WorkerLoop(std::stop_token &stop_token) noexcept;

  static void
  ShutdownGlobalPool() noexcept
  {
    delete sGlobalThreadPool;
  }

private:
  std::shared_ptr<TaskBase> TakeFront();

  static ThreadPool *sGlobalThreadPool;
  std::vector<std::unique_ptr<DebuggerThread>> mThreadPool;
  std::queue<std::shared_ptr<TaskBase>> mTaskQueue;
  std::queue<std::unique_ptr<TaskGroup>> mTaskGroup;
  std::mutex mTaskMutex;
  std::condition_variable mTaskConditionVariable;
};
} // namespace mdb