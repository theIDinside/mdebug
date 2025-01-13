/** LICENSE TEMPLATE */
#include "thread_pool.h"
#include "utils/debugger_thread.h"
#include "utils/worker_task.h"
#include <sys/prctl.h>
#include <utils/signals.h>

namespace utils {

/*static*/ ThreadPool *
ThreadPool::get_global_pool() noexcept
{
  return global_thread_pool;
}

void
ThreadPool::post_task(Task *task) noexcept
{
  std::lock_guard lock(m_task_mutex);
  m_task_queue.push(task);
  m_task_cv.notify_one();
}

void
ThreadPool::post_tasks(std::span<Task *> tasks) noexcept
{
  std::lock_guard lock(m_task_mutex);
  for (auto t : tasks) {
    m_task_queue.push(t);
  }
  m_task_cv.notify_all();
}

ThreadPool::ThreadPool() noexcept : thread_pool(), m_task_queue(), m_groups(), m_task_mutex(), m_task_cv() {}

ThreadPool::~ThreadPool()
{
  auto tasks = shutdown_tasks();
  for (auto &t : thread_pool) {
    t.request_stop();
  }
  for (auto t : tasks) {
    post_task(t);
  }
}

void
ThreadPool::initialize(u32 pool_size) noexcept
{
  thread_pool.reserve(pool_size);
  for (auto i = 0u; i < pool_size; ++i) {
    thread_pool.emplace_back([this, i](auto stop_token) {
      DebuggerThread::AssertSigChildIsBlocked();
      const auto name = "mdb-pool-" + std::to_string(i);
      worker(stop_token, name.c_str());
    });
  }
}

u32
ThreadPool::worker_count() const noexcept
{
  return thread_pool.size();
}

std::vector<Task *>
ThreadPool::shutdown_tasks() noexcept
{
  std::vector<Task *> res;
  const auto sz = worker_count();
  res.reserve(sz);
  for (auto i = 0u; i < sz; ++i) {
    res.push_back(new NoOp{});
  }
  return res;
}

void
ThreadPool::worker(std::stop_token stop_token, const char *name) noexcept
{
  VERIFY(prctl(PR_SET_NAME, name) != -1, "Failed to set worker thread name");
  ScopedBlockedSignals blocked_sigs{std::array{SIGCHLD}};
  DBGLOG(core, "Worker thread {} spawned", name);
  while (true && !stop_token.stop_requested()) {
    Task *job = nullptr;
    {
      std::unique_lock lock(m_task_mutex);
      while (m_task_queue.empty()) {
        m_task_cv.wait(lock);
      }
      job = m_task_queue.front();
      m_task_queue.pop();
    }
    ASSERT(job != nullptr, "Failed to retrieve work from task queue");
    job->execute();
    delete job;
  }
}
} // namespace utils