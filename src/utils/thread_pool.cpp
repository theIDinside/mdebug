#include "thread_pool.h"
#include <linux/prctl.h>
#include <sys/prctl.h>

namespace utils {

ThreadPool::ThreadPool() noexcept : thread_pool(), m_task_queue(), m_task_mutex(), m_task_cv() {}

void
ThreadPool::initialize(u32 pool_size) noexcept
{
  thread_pool.reserve(pool_size);
  const auto cap = thread_pool.capacity();
  thread_pool.reserve(cap);
  for (auto i = 0u; i < cap; i++) {
    thread_pool.emplace_back([this, i](auto stop_token) {
      auto name = "mdb-worker-" + std::to_string(i);
      this->worker_spawn(stop_token, name.c_str());
    });
  }
}

/*static */ ThreadPool *
ThreadPool::get_global_pool() noexcept
{
  ASSERT(global_thread_pool != nullptr, "Thread pool not initialized");
  return global_thread_pool;
}

u32
ThreadPool::worker_count() const noexcept
{
  return thread_pool.size();
}

void
ThreadPool::worker_spawn(std::stop_token stop_token, const char *worker_name) noexcept
{
  if (-1 == prctl(PR_SET_NAME, worker_name))
    PANIC("Failed to set name for worker thread");
  DLOG("mdb", "{} spawned...", worker_name);
  while (true && !stop_token.stop_requested()) {
    Task *t;
    {
      std::unique_lock<std::mutex> lock(m_task_mutex);
      while (m_task_queue.empty())
        m_task_cv.wait(lock);
      t = m_task_queue.front();
      m_task_queue.pop();
    }
    ASSERT(t != nullptr, "Failed to get task");
    t->execute();
    delete t;
  }
}

void
ThreadPool::post_task(Task *task) noexcept
{
  std::lock_guard lock(m_task_mutex);
  m_task_queue.push(task);
  m_task_cv.notify_one();
}

} // namespace utils