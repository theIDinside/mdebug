#pragma once
#include <chrono>
#include <future>
#include <vector>

namespace utils {
class TaskGroup;

class Task
{
public:
  Task() noexcept = default;
  virtual ~Task() noexcept = default;
  void set_owner(TaskGroup *group) noexcept;
  void execute() noexcept;

protected:
  virtual void execute_task() noexcept = 0;

private:
  bool is_group_job() const noexcept;
  TaskGroup *owning_group;
};

using JobPtr = Task *;

class TaskGroup
{
public:
  TaskGroup(std::string_view name) noexcept;
  ~TaskGroup() noexcept = default;

  void add_task(Task *task) noexcept;
  std::future<void> schedule_work() noexcept;
  void task_done(Task *task) noexcept;

private:
  std::enable_if_t<MDB_DEBUG == 1, std::chrono::high_resolution_clock::time_point> start;
  std::promise<void> m_promise;
  std::string_view m_name;
  std::mutex m_task_lock;
  std::vector<Task *> m_tasks;
  std::vector<Task *> m_done_tasks;
};
} // namespace utils