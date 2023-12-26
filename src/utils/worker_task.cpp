#include "worker_task.h"
#include "../common.h"
#include "thread_pool.h"
#include <chrono>

extern bool LogTaskGroup;

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

TaskGroup::TaskGroup(std::string_view name) noexcept : m_promise(), m_name(name), m_task_lock(), m_done_tasks()
{
  DLOG("mdb", "Created task group {}", name);
}

TaskGroup::~TaskGroup() noexcept
{
  if (LogTaskGroup)
    LOG("mdb", "Task group {} finished - destroying task group", m_name);
}

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
  if (LogTaskGroup) {
    LOG("mdb", "[TG: {}] - Scheduling {} tasks", m_name, m_tasks.size());
    start = std::chrono::high_resolution_clock::now();
  }
  auto fut = m_promise.get_future();
  m_done_tasks.reserve(m_tasks.size());
  ThreadPool::get_global_pool()->post_tasks(m_tasks);
  return fut;
}

void
TaskGroup::task_done(Task *task) noexcept
{
  std::lock_guard lock(m_task_lock);
  if (std::ranges::any_of(m_done_tasks, [task](auto t) { return t == task; })) {
    std::vector<std::uintptr_t> tasks_{};
    std::transform(m_done_tasks.begin(), m_done_tasks.end(), std::back_inserter(tasks_),
                   [](auto t) { return std::uintptr_t(t); });
    ASSERT(false, "Task 0x{:x} has already been added to done list: [0x{:x}]", std::uintptr_t(task),
           fmt::join(tasks_, ", "));
  }
  m_done_tasks.push_back(task);
  if (m_done_tasks.size() == m_tasks.size()) {
    if (LogTaskGroup) {
      auto time =
          std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
              .count();
      LOG("mdb", "[TG {}]: done, time={}us", m_name, time);
    }
    m_promise.set_value();
  }
}

} // namespace utils