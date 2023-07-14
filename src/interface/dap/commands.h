#pragma once
#include "../ui_command.h"
// NOLINTNEXTLINE
#include "../../breakpoint.h"
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
  DEFINE_NAME(Continue)
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(BreakpointType type) noexcept;
  BreakpointType type;
  std::vector<ui::dap::Breakpoint> breakpoints;
  ~SetBreakpointsResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(nlohmann::json &&arguments) noexcept;
  ~SetInstructionBreakpoints() = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(SetInstructionBreakpoints)
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(nlohmann::json &&arguments) noexcept;
  ~SetFunctionBreakpoints() = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(SetInstructionBreakpoints)
};

ui::UICommand *parse_command(Command cmd, nlohmann::json &&args) noexcept;
}; // namespace ui::dap