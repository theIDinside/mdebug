/** LICENSE TEMPLATE */
#pragma once
#include "ui_command.h"
#include <memory_resource>
#include <string>

namespace mdb::ui {

struct UIResult
{
  // Events contruct UIResult like so:
  constexpr UIResult(SessionId sessionId) noexcept : mSessionId(sessionId), mSuccess(true), mRequestSeq(0) {}

  // Responses from commands construct UIResult:
  constexpr UIResult(bool success, UICommandPtr cmd) noexcept
      : mSessionId(cmd->mSessionId), mSuccess(success), mRequestSeq(cmd->mSeq), mClient(cmd->mDAPClient)
  {
  }

  virtual ~UIResult() = default;

  virtual std::pmr::string Serialize(int monotonicId, std::pmr::memory_resource *allocator) const noexcept = 0;

  SessionId
  GetSessionId() const noexcept
  {
    return mSessionId;
  }

  SessionId mSessionId;
  bool mSuccess;
  std::uint64_t mRequestSeq;
  ui::dap::DebugAdapterClient *mClient;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UIResultPtr = const UIResult *;
} // namespace mdb::ui
