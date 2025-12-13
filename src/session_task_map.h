/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <utils/smartptr.h>

// std
#include <unordered_map>

namespace mdb {

class TaskInfo;

class SessionTaskMap
{
  u32 mSessionThreadId{ 0 };
  std::unordered_map<Tid, RefPtr<TaskInfo>> mThreads{};
  std::vector<std::pair<u32, RefPtr<TaskInfo>>> mThreadById{};

public:
  TaskInfo *Get(Tid tid) noexcept;
  TaskInfo *GetBySessionId(u32 id) noexcept;
  void Add(Tid tid, TaskInfo *t) noexcept;
  std::span<std::pair<u32, RefPtr<TaskInfo>>> AllThreads() noexcept;
};
} // namespace mdb