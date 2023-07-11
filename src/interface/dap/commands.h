#pragma once
#include "../ui_command.h"
// NOLINTNEXTLINE
#include "dap_defs.h"
#include "nlohmann/json.hpp"
#include "types.h"
#include <tuple>
#include <vector>

namespace ui::dap {

struct Breakpoint;

struct ContinueResponse final : ui::UIResult
{
  ~ContinueResponse() noexcept = default;
  bool continue_all;
  std::string serialize(int seq) const noexcept final override;
};

struct Continue final : public ui::UICommand
{
  int thread_id;
  bool continue_all;
  Continue(int tid, bool all) noexcept : thread_id(tid), continue_all(all) {}
  ~Continue() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
};

struct SetInstructionBreakpointsResponse final : ui::UIResult
{
  std::vector<ui::dap::Breakpoint> breakpoints;
  ~SetInstructionBreakpointsResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(nlohmann::json &&arguments) noexcept;
  ~SetInstructionBreakpoints() = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
};

ui::UICommand *parse_command(Command cmd, nlohmann::json &&args) noexcept;
}; // namespace ui::dap