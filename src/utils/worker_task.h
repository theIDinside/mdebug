/** LICENSE TEMPLATE */
#pragma once
#include <future>
#include <lib/arena_allocator.h>
#include <memory_resource>
#include <vector>

namespace mdb {
class TaskGroup;

class Task
{
public:
  Task() noexcept = default;
  virtual ~Task() noexcept = default;
  void SetOwner(TaskGroup *group) noexcept;
  void Execute() noexcept;

protected:
  virtual void ExecuteTask(std::pmr::memory_resource *temporaryAllocator) noexcept = 0;

private:
  bool IsGroupJob() const noexcept;
  TaskGroup *mOwningGroup{ nullptr };
};

class NoOp final : public Task
{
public:
  NoOp() noexcept : Task() {}
  ~NoOp() noexcept override = default;

protected:
  void ExecuteTask(std::pmr::memory_resource *temporaryAllocator) noexcept final;
};

using JobPtr = Task *;

class TaskGroup
{
  pid_t mPid;

public:
  TaskGroup(std::string_view name) noexcept;
  ~TaskGroup() noexcept = default;

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

  alloc::ArenaResource *GetTemporaryAllocator() const noexcept;

private:
  std::promise<void> mPromise;
  std::string_view mName;
  std::mutex mTaskLock;
  std::vector<Task *> mTasks;
  std::vector<Task *> mDoneTasks;
  std::unique_ptr<alloc::ArenaResource> mGroupTemporaryAllocator;
};
} // namespace mdb