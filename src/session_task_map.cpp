/** LICENSE TEMPLATE */

#include "session_task_map.h"

// mdb
#include <task.h>

namespace mdb {
TaskInfo *
SessionTaskMap::Get(Tid tid) noexcept
{
  auto task = mThreads[tid];
  return task;
}

void
SessionTaskMap::Add(Tid tid, TaskInfo *t) noexcept
{
  MDB_ASSERT(!mThreads.contains(tid) || mThreads[tid] == nullptr, "Thread already added");
  RefPtr task{ t };
  mThreads[tid] = task;

  const auto taskSessionId = mSessionThreadId++;
  t->mSessionId = taskSessionId;
  mThreadById.push_back(std::make_pair(taskSessionId, std::move(task)));
}

std::span<std::pair<u32, RefPtr<TaskInfo>>>
SessionTaskMap::AllThreads() noexcept
{
  return std::span{ mThreadById };
}

TaskInfo *
SessionTaskMap::GetBySessionId(u32 id) noexcept
{
  for (const auto &entry : mThreadById) {
    if (entry.first == id) {
      return entry.second;
    }
  }

  return nullptr;
}

} // namespace mdb
