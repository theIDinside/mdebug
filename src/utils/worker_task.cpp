#include "worker_task.h"
#include "thread_pool.h"
#include <algorithm>
#include <chrono>
#include <common.h>
#include <mutex>

namespace utils {

TaskGroup::TaskGroup(std::string_view name) noexcept
    : m_promise(), m_name(name), m_task_lock(), m_tasks(), m_done_tasks()
{
}

TaskGroup::~TaskGroup() {}

void
TaskGroup::done(Task *t) noexcept
{
  std::lock_guard lock(m_task_lock);
  m_done_tasks.push_back(t);
  if (m_done_tasks.size() == m_tasks.size()) {
    auto time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() -
                                                                      schedule_start)
                    .count();
    DLOG("mdb", "[TG {}]: done, time={}us", m_name, time);
    m_promise.set_value();
  }
}

std::future<void>
TaskGroup::schedule_tasks() noexcept
{
  schedule_start = std::chrono::high_resolution_clock::now();
  auto fut = m_promise.get_future();
  m_done_tasks.reserve(m_tasks.size());
  for (auto w : m_tasks) {
    ThreadPool::get_global_pool()->post_task(w);
  }
  return fut;
}

void
TaskGroup::add_task(Task *task) noexcept
{
  std::lock_guard lock(m_task_lock);
  m_tasks.push_back(task);
  task->set_owner(this);
}

void
TaskGroup::wait(int yield_by_ms) noexcept
{
  auto fut = m_promise.get_future();
  fut.get();
}

void
Task::set_owner(TaskGroup *group_owner) noexcept
{
  owner = group_owner;
}

void
Task::execute() noexcept
{
  execute_task();
  if (owner)
    owner->done(this);
}
} // namespace utils