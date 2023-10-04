#pragma once
#include <chrono>
#include <condition_variable>
#include <future>
#include <string_view>
#include <vector>

namespace utils {

enum class TaskResult : int
{
  Ok = 0,
  Cancelled = 1,
  Error = -1
};

class Task;

class TaskGroup
{
public:
  TaskGroup(std::string_view name) noexcept;
  ~TaskGroup();

  // Register a task with this task group. This does not spawn or start the job/work. To schedule the tasks,
  // `schedule` is to be used; but this is only after all tasks has been registered. Once scheduling has started,
  // no more new tasks should be added to the task group. Though this might technically work, it's not the intended
  // design.
  void add_task(Task *task) noexcept;

  // Schedules the tasks registered with this TaskGroup to the global thread pool. In future iterations, this can
  // be made more generic but, seeing as how most work will register its results to a "container type" (like
  // ObjectFile, CompilationUnit, etc), there's no point right now to return results, and instead use
  // std::future<void> as a signalling type for a batched job to be "done".
  std::future<void> schedule_tasks() noexcept;
  // "callback", performed by registered Tasks to inform the TaskGroup when they've performed their job.
  void done(Task *t) noexcept;
  // The interface to use when wanting to wait (synchronize-with) a task group, waiting until all tasks has
  // completed.
  void wait(int yield_by_ms) noexcept;

private:
  std::chrono::time_point<std::chrono::high_resolution_clock> schedule_start;
  std::promise<void> m_promise;
  std::string_view m_name;
  std::mutex m_task_lock;
  std::vector<Task *> m_tasks;
  std::vector<Task *> m_done_tasks;
};

// Worker task base class
class Task
{
public:
  Task() noexcept = default;
  virtual ~Task() = default;
  void set_owner(TaskGroup *owner) noexcept;
  void execute() noexcept;
  virtual void execute_task() noexcept = 0;

private:
  TaskGroup *owner;
};
} // namespace utils