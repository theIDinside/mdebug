/** LICENSE TEMPLATE */
#pragma once
#include <future>
#include <lib/arena_allocator.h>
#include <memory_resource>
#include <vector>

namespace mdb {
class TaskGroup;

class TaskBase
{
public:
  TaskBase() noexcept = default;
  virtual ~TaskBase() noexcept;

  virtual void Execute() noexcept = 0;
  void Cancel() noexcept;
  [[nodiscard]] bool IsCancelled() const noexcept;

protected:
  bool mIsCancelled{ false };
};

class StandardTask : public TaskBase
{
public:
  virtual ~StandardTask() noexcept override = default;
  void SetOwner(TaskGroup *group) noexcept;
  void Execute() noexcept override;

protected:
  virtual void ExecuteTask(std::pmr::memory_resource *temporaryAllocator) noexcept = 0;
  TaskGroup *mOwningGroup{ nullptr };
};

class NoOp final : public StandardTask
{
public:
  NoOp() noexcept = default;
  ~NoOp() noexcept override = default;

protected:
  void ExecuteTask(std::pmr::memory_resource *temporaryAllocator) noexcept final;
};

class TaskGroup
{
  pid_t mPid;

public:
  TaskGroup(std::string_view name) noexcept;
  ~TaskGroup() noexcept = default;

  void
  AddTasks(std::span<std::shared_ptr<StandardTask>> tasks) noexcept
  {
    std::lock_guard lock(mTaskLock);
    for (std::shared_ptr<StandardTask> t : tasks) {
      t->SetOwner(this);
      mTasks.push_back(std::move(t));
    }
  }
  std::future<void> ScheduleWork() noexcept;
  void TaskDone(StandardTask *task) noexcept;

  alloc::ArenaResource *GetTemporaryAllocator() const noexcept;

private:
  std::promise<void> mPromise;
  std::string_view mName;
  std::mutex mTaskLock;
  std::vector<std::shared_ptr<TaskBase>> mTasks;
  std::vector<StandardTask *> mDoneTasks;
  std::unique_ptr<alloc::ArenaResource> mGroupTemporaryAllocator;
};
} // namespace mdb