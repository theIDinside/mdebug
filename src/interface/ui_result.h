/** LICENSE TEMPLATE */
#pragma once
#include "ui_command.h"
#include <memory_resource>
#include <string>

namespace mdb::ui {

struct UIResult
{
  // Events contruct UIResult like so:
  constexpr UIResult(Pid processId) noexcept : mPid(processId), success(true), requestSeq(0) {}

  // Responses from commands construct UIResult:
  constexpr UIResult(bool success, UICommandPtr cmd) noexcept
      : mPid(cmd->mPid), success(success), requestSeq(cmd->seq), client(cmd->mDAPClient)
  {
  }
  virtual ~UIResult() = default;
  virtual std::pmr::string Serialize(int monotonic_id, std::pmr::memory_resource *allocator) const noexcept = 0;

  Pid
  ProcessId() const noexcept
  {
    return mPid;
  }

  Pid mPid;
  bool success;
  std::uint64_t requestSeq;
  ui::dap::DebugAdapterClient *client;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UIResultPtr = const UIResult *;
} // namespace mdb::ui
