#pragma once
#include "worker_task.h"
#include <common.h>
#include <condition_variable>
#include <future>
#include <queue>
#include <thread>

namespace utils {

class ThreadPool
{
public:
  static ThreadPool *global_thread_pool;
  ThreadPool() noexcept;
  ~ThreadPool();
  void initialize(u32 pool_size) noexcept;
  void post_task(Task *task) noexcept;
  void worker_spawn(std::stop_token stop_token, const char *worker_name) noexcept;
  static ThreadPool *get_global_pool() noexcept;
  u32 worker_count() const noexcept;

  template <typename FutureResult>
  std::future<FutureResult>
  post_task_group(TaskGroup *group)
  {
  }

  // Takes a range of `work` and calculates how to split that up into N batches, where N is the total amount of
  // worker threads. The returned result is the size of each individual batch of work. T must have the member
  // function `size`.
  template <typename T>
  static std::vector<u32>
  work_sizes(const T &work, u32 min_batch_size) noexcept
  {
    auto pool = utils::ThreadPool::get_global_pool();
    const auto worker_count = pool->worker_count();
    if (work.size() < min_batch_size)
      return std::vector<u32>{static_cast<u32>(work.size())};
    auto batching = work.size() / worker_count;
    std::vector<u32> counts{};
    counts.reserve(worker_count);
    while (counts.size() < worker_count) {
      counts.push_back(batching);
    }
    // add remainder of work to last task
    ASSERT(batching * worker_count <= work.size(), "Division of labor failed");
    counts.back() += work.size() - (batching * worker_count);
    return counts;
  }

private:
  std::vector<std::jthread> thread_pool;
  std::queue<Task *> m_task_queue;
  std::queue<std::unique_ptr<TaskGroup>> m_groups;
  std::mutex m_task_mutex;
  std::condition_variable m_task_cv;
};
} // namespace utils