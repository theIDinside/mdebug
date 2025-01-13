/** LICENSE TEMPLATE */
#pragma once
#include "ui_command.h"
#include <memory_resource>
#include <string>

namespace ui {

struct UIResult
{
  UIResult() = default;
  UIResult(bool success, UICommandPtr cmd = nullptr) noexcept
      : success(success), request_seq((cmd != nullptr) ? cmd->seq : 0), client(cmd->dap_client)
  {
  }
  virtual ~UIResult() = default;
  virtual std::pmr::string Serialize(int monotonic_id, std::pmr::memory_resource* allocator) const noexcept = 0;

  bool success;
  std::uint64_t request_seq;
  ui::dap::DebugAdapterClient *client;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UIResultPtr = const UIResult *;
} // namespace ui
