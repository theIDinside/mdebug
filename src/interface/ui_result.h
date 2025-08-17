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
      : mSessionId(cmd->mSessionId), mSuccess(success), mRequestSeq(cmd->mSeq),
        mAllocator(std::move(cmd->mCommandAllocator)), mClient(cmd->mDAPClient)
  {
  }

  virtual ~UIResult() = default;

  virtual std::pmr::string Serialize(int monotonicId, std::pmr::memory_resource *allocator) const noexcept = 0;

  // Command & Result own an allocator for their collective life time and release all allocations up execution and
  // serialization of the result whereas Events receive a allocator in argument at serialization time, since there
  // may be multiple events waiting to be serialized, using a bump allocator for all of them is better.
  constexpr std::pmr::string
  Serialize(int monotonicId) const noexcept
  {
    return Serialize(monotonicId, mAllocator->GetAllocator());
  }

  SessionId
  GetSessionId() const noexcept
  {
    return mSessionId;
  }

  SessionId mSessionId;
  bool mSuccess;
  std::uint64_t mRequestSeq;
  UICommand::RequestResponseAllocator mAllocator;
  ui::dap::DebugAdapterClient *mClient;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UIResultPtr = const UIResult *;
} // namespace mdb::ui
