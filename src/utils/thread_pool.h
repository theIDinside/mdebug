#pragma once
#include "../common.h"
#include "worker_task.h"
#include <numeric>
#include <queue>
#include <thread>
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
  void initialize(u32 pool_size) noexcept;
  u32 worker_count() const noexcept;
  static ThreadPool *get_global_pool() noexcept;
  void post_task(Task *task) noexcept;
  void post_tasks(std::span<Task *> tasks) noexcept;
  void worker(std::stop_token stop_token, const char *name) noexcept;

  template <Containerish T>
  static std::vector<u32>
  calculate_job_sizes(const T &container_of_works)
  {
    const auto worker_threads = ThreadPool::get_global_pool()->worker_count();
    if (container_of_works.size() < worker_threads) {
      std::vector<u32> worksize_per_thread{};
      worksize_per_thread.reserve(container_of_works.size());
      for (auto i = 0u; i < container_of_works.size(); i++)
        worksize_per_thread.push_back(1);
      return worksize_per_thread;
    }
    const auto batching = container_of_works.size() / worker_threads;
    std::vector<u32> worksize_per_thread{};
    worksize_per_thread.reserve(worker_threads);
    while (worksize_per_thread.size() < worker_threads) {
      worksize_per_thread.push_back(batching);
    }
    ASSERT(batching * worker_threads <= container_of_works.size(), "Division of job sizes failed");
    // If there was a remainder after (container_of_works.size() / worker_threads), add that remainder to last
    // worker's job count.
    worksize_per_thread.back() += container_of_works.size() - (batching * worker_threads);
    ASSERT(std::accumulate(worksize_per_thread.begin(), worksize_per_thread.end(), 0u) ==
               container_of_works.size(),
           "Sum of total jobs doesn't amount to {}", container_of_works.size());
    return worksize_per_thread;
  }

private:
  static ThreadPool *global_thread_pool;
  std::vector<std::jthread> thread_pool;
  std::queue<Task *> m_task_queue;
  std::queue<std::unique_ptr<TaskGroup>> m_groups;
  std::mutex m_task_mutex;
  std::condition_variable m_task_cv;
};
} // namespace utils