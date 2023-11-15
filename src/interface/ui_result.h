#pragma once
#include "ui_command.h"
#include <concepts>
#include <cstdint>
#include <string>

namespace ui {
struct UIResult
{
  UIResult() = default;
  UIResult(bool success, UICommandPtr cmd = nullptr) noexcept
      : success(success), response_seq((cmd != nullptr) ? cmd->seq : 0)
  {
  }
  virtual ~UIResult() = default;
  virtual std::string serialize(int monotonic_id) const noexcept = 0;

  bool success;
  std::uint64_t response_seq;
};

// Makes it *somewhat* easier to re-factoer later, if we want to use shared_ptr or unique_ptr here
using UIResultPtr = const UIResult *;
} // namespace ui
