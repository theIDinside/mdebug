#pragma once
#include "../common.h"
#include "worker_task.h"
#include <queue>
#include <thread>
#include <vector>

namespace utils {
class ThreadPool
{
public:
  ThreadPool() noexcept;
  ~ThreadPool();
  void initialize(u32 pool_size) noexcept;
  static ThreadPool *get_global_pool() noexcept;
  void post_task(Task *task) noexcept;
  void worker(std::stop_token stop_token, const char *name) noexcept;

private:
  static ThreadPool *global_thread_pool;
  std::vector<std::jthread> thread_pool;
  std::queue<Task *> m_task_queue;
  std::queue<std::unique_ptr<TaskGroup>> m_groups;
  std::mutex m_task_mutex;
  std::condition_variable m_task_cv;
};
} // namespace utils