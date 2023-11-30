#include "worker_task.h"
#include "../common.h"
#include "thread_pool.h"
#include <chrono>

namespace utils {

void
Task::set_owner(TaskGroup *group) noexcept
{
  ASSERT(owning_group == nullptr, "Moving owning task group for task is not allowed");
  owning_group = group;
}

bool
Task::is_group_job() const noexcept
{
  return owning_group != nullptr;
}

void
Task::execute() noexcept
{
  execute_task();
  if (is_group_job()) {
    owning_group->task_done(this);
  }
}

TaskGroup::TaskGroup(std::string_view name) noexcept : m_promise(), m_name(name), m_task_lock(), m_done_tasks() {}

void
TaskGroup::add_task(Task *task) noexcept
{
  std::lock_guard lock(m_task_lock);
  m_tasks.push_back(task);
  task->set_owner(this);
}

std::future<void>
TaskGroup::schedule_work() noexcept
{
  if constexpr (MDB_DEBUG == 1) {
    start = std::chrono::high_resolution_clock::now();
  }
  auto fut = m_promise.get_future();
  m_done_tasks.reserve(m_tasks.size());
  for (auto w : m_tasks) {
    ThreadPool::get_global_pool()->post_task(w);
  }
  return fut;
}

void
TaskGroup::task_done(Task *task) noexcept
{
  std::lock_guard lock(m_task_lock);
  m_done_tasks.push_back(task);
  ASSERT(!std::ranges::any_of(m_done_tasks, [task](auto t) { return t == task; }),
         "Task has already been added to done list!");
  if (m_done_tasks.size() == m_tasks.size()) {
    if constexpr (MDB_DEBUG == 1) {
      auto time =
          std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
              .count();
      DLOG("mdb", "[TG {}]: done, time={}us", m_name, time);
    }
    m_promise.set_value();
  }
}

} // namespace utils