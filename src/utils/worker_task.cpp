/** LICENSE TEMPLATE */
#include "worker_task.h"
#include "../common.h"
#include "fmt/ranges.h"
#include "lib/arena_allocator.h"
#include "log.h"
#include "thread_pool.h"
#include "utils/logger.h"
#include <chrono>

namespace utils {

void
Task::SetOwner(TaskGroup *group) noexcept
{
  ASSERT(mOwningGroup == nullptr, "Moving owning task group for task is not allowed");
  mOwningGroup = group;
}

bool
Task::IsGroupJob() const noexcept
{
  return mOwningGroup != nullptr;
}

void
Task::Execute() noexcept
{
  auto allocator = mOwningGroup ? mOwningGroup->GetTemporaryAllocator() : nullptr;
  ExecuteTask(allocator);
  if (IsGroupJob()) {
    mOwningGroup->TaskDone(this);
  }
}

void
NoOp::ExecuteTask(std::pmr::memory_resource* temporaryAllocator) noexcept
{
}

TaskGroup::TaskGroup(std::string_view name) noexcept : mPromise(), mName(name), mTaskLock(), mDoneTasks()
{
  DBGLOG(perf, "Created task group {}", name);
  mGroupTemporaryAllocator = alloc::ArenaAllocator::Create(alloc::Page{10000}, nullptr);
}

TaskGroup::~TaskGroup() noexcept
{
  CDLOG(mdb::log::Config::LogTaskGroup(), perf, "Task group {} finished - destroying task group", mName);
}

void
TaskGroup::AddTask(Task *task) noexcept
{
  std::lock_guard lock(mTaskLock);
  mTasks.push_back(task);
  task->SetOwner(this);
}

std::future<void>
TaskGroup::ScheduleWork() noexcept
{
  CDLOG(mdb::log::Config::LogTaskGroup(), perf, "[TG: {}] - Scheduling {} tasks", mName, mTasks.size());
  if (mdb::log::Config::LogTaskGroup()) {
    mStart = std::chrono::high_resolution_clock::now();
  }
  auto fut = mPromise.get_future();
  mDoneTasks.reserve(mTasks.size());
  ThreadPool::GetGlobalPool()->PostTasks(mTasks);
  return fut;
}

void
TaskGroup::TaskDone(Task *task) noexcept
{
  std::lock_guard lock(mTaskLock);
  if (std::ranges::any_of(mDoneTasks, [task](auto t) { return t == task; })) {
    std::vector<std::uintptr_t> tasks_{};
    std::transform(mDoneTasks.begin(), mDoneTasks.end(), std::back_inserter(tasks_),
                   [](auto t) { return std::uintptr_t(t); });
    ASSERT(false, "Task 0x{:x} has already been added to done list: [0x{:x}]", std::uintptr_t(task),
           fmt::join(tasks_, ", "));
  }
  mDoneTasks.push_back(task);
  if (mDoneTasks.size() == mTasks.size()) {
    if (mdb::log::Config::LogTaskGroup()) {
      auto time =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - mStart)
          .count();

      CDLOG(mdb::log::Config::LogTaskGroup(), perf, "[TG {}]: done, time={}us", mName, time);
    }
    mPromise.set_value();
  }
}

alloc::ArenaAllocator *
TaskGroup::GetTemporaryAllocator() const noexcept
{
  return mGroupTemporaryAllocator.get();
}

} // namespace utils