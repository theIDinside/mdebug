/** LICENSE TEMPLATE */
#include "worker_task.h"

#include "../common.h"
#include "lib/arena_allocator.h"
#include "thread_pool.h"
#include "utils/format_utils.h"
#include "utils/logger.h"
#include <algorithm>

namespace mdb {

TaskBase::~TaskBase() noexcept
{
#ifdef DEBUG
  DBGBUFLOG(core, "TaskBase destructor");
#endif
}

void
TaskBase::Cancel() noexcept
{
  mIsCancelled = true;
}

[[nodiscard]]
bool
TaskBase::IsCancelled() const noexcept
{
  return mIsCancelled;
}

void
StandardTask::SetOwner(TaskGroup *group) noexcept
{
  MDB_ASSERT(mOwningGroup == nullptr, "Moving owning task group for task is not allowed");
  mOwningGroup = group;
}

void
StandardTask::Execute() noexcept
{
  auto *allocator = mOwningGroup ? mOwningGroup->GetTemporaryAllocator() : nullptr;
  ExecuteTask(allocator);
  mOwningGroup->TaskDone(this);
}

void
NoOp::ExecuteTask([[maybe_unused]] std::pmr::memory_resource *temporaryAllocator) noexcept
{
  (void)temporaryAllocator;
}

TaskGroup::TaskGroup(std::string_view name) noexcept : mName(name)
{
  mGroupTemporaryAllocator = alloc::ArenaResource::CreateUniquePtr(alloc::Page{ 10000 });
}

std::future<void>
TaskGroup::ScheduleWork() noexcept
{
  mPid = gettid();
  PROFILE_BEGIN_PID(mName, "TaskGroups", mPid);
  auto fut = mPromise.get_future();
  mDoneTasks.reserve(mTasks.size());
  ThreadPool::GetGlobalPool()->PostTasks(mTasks);
  return fut;
}

void
TaskGroup::TaskDone(StandardTask *task) noexcept
{
  std::lock_guard lock(mTaskLock);
#ifdef DEBUG
  if (std::ranges::any_of(mDoneTasks, [task](auto t) { return t == task; })) {
    std::vector<std::uintptr_t> tasks_{};
    std::ranges::transform(mDoneTasks, std::back_inserter(tasks_), [](auto t) { return std::uintptr_t(t); });
    MDB_ASSERT(false,
      "Task 0x{:x} has already been added to done list: [{}]",
      std::uintptr_t(task),
      HexJoinFormatIterator{ tasks_, ", " });
  }
#endif
  mDoneTasks.push_back(task);
  if (mDoneTasks.size() == mTasks.size()) {
    PROFILE_END_PID(mName, "TaskGroups", mPid);
    mPromise.set_value();
  }
}

alloc::ArenaResource *
TaskGroup::GetTemporaryAllocator() const noexcept
{
  return mGroupTemporaryAllocator.get();
}

} // namespace mdb