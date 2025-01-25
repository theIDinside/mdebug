/** LICENSE TEMPLATE */
#pragma once
#include <chrono>
#include <future>
#include <vector>
#include <memory_resource>

namespace alloc {
  class ArenaAllocator;
};

void SetTaskGroupLog(bool value) noexcept;
namespace utils {
class TaskGroup;

class Task
{
public:
  Task() noexcept = default;
  virtual ~Task() noexcept = default;
  void SetOwner(TaskGroup *group) noexcept;
  void Execute() noexcept;

protected:
  virtual void ExecuteTask(std::pmr::memory_resource* temporaryAllocator) noexcept = 0;

private:
  bool IsGroupJob() const noexcept;
  TaskGroup *mOwningGroup{nullptr};
};

class NoOp final : public Task
{
public:
  NoOp() noexcept = default;
  ~NoOp() noexcept override = default;

protected:
  void ExecuteTask(std::pmr::memory_resource* temporaryAllocator) noexcept final;
};

using JobPtr = Task *;

class TaskGroup
{
public:
  TaskGroup(std::string_view name) noexcept;
  ~TaskGroup() noexcept;

  void AddTask(Task *task) noexcept;

  template <typename Task>
  void
  AddTasks(std::span<Task *> tasks) noexcept
  {
    std::lock_guard lock(mTaskLock);
    for (auto t : tasks) {
      mTasks.push_back(t);
      t->SetOwner(this);
    }
  }
  std::future<void> ScheduleWork() noexcept;
  void TaskDone(Task *task) noexcept;

  alloc::ArenaAllocator* GetTemporaryAllocator() const noexcept;

private:
  std::chrono::high_resolution_clock::time_point mStart;
  std::promise<void> mPromise;
  std::string_view mName;
  std::mutex mTaskLock;
  std::vector<Task *> mTasks;
  std::vector<Task *> mDoneTasks;
  std::unique_ptr<alloc::ArenaAllocator> mGroupTemporaryAllocator;
};
} // namespace utils