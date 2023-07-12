#include "commands.h"
#include "../../target.h"
#include "../../tracer.h"
#include "fmt/format.h"
#include "types.h"
#include <algorithm>
#include <memory>
#include <ranges>
namespace ui::dap {

std::string
ContinueResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "type": "response", "success": true, "command": "continue", "body": {{ "allThreadsContinued": {} }} }})",
      seq, continue_all);
}

UIResultPtr
Continue::execute(Tracer *tracer) noexcept
{
  auto target = tracer->get_current();
  target->set_all_running(RunType::Continue);

  auto res = new ContinueResponse{};
  res->continue_all = continue_all;
  return res;
}

SetInstructionBreakpoints::SetInstructionBreakpoints(nlohmann::json &&arguments) noexcept
    : args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetInstructionBreakpoints::execute(Tracer *tracer) noexcept
{
  using BP = ui::dap::Breakpoint;
  std::vector<AddrPtr> addresses;
  addresses.reserve(args.at("breakpoints").size());
  for (const auto &ibkpt : args.at("breakpoints")) {
    ASSERT(ibkpt.contains("instructionReference") && ibkpt["instructionReference"].is_string(),
           "instructionReference field not in args or wasn't of type string");
    std::string_view addr_str;
    ibkpt["instructionReference"].get_to(addr_str);
    auto addr = to_addr(addr_str);
    ASSERT(addr.has_value(), "Couldn't parse address from {}", addr_str);
    addresses.push_back(*addr);
  }
  auto target = tracer->get_current();
  target->reset_breakpoints(addresses);

  auto res = new SetInstructionBreakpointsResponse{};
  res->breakpoints.reserve(target->bkpt_map.breakpoints.size());

  for (const auto &[addr, bp] : target->bkpt_map.breakpoints) {
    res->breakpoints.push_back(BP{
        .id = bp.bp_id,
        .verified = true,
        .addr = addr,
    });
  }
  ASSERT(res->breakpoints.size() == addresses.size(), "Response value size does not match result size");
  return res;
}

std::string
SetInstructionBreakpointsResponse::serialize(int seq) const noexcept
{
  std::vector<std::string> serialized_bkpts{};
  serialized_bkpts.reserve(breakpoints.size());
  for (auto &bp : breakpoints) {
    serialized_bkpts.push_back(bp.serialize());
  }
  return fmt::format(
      R"({{ "seq": {}, "type": "response", "success": true, "command": "continue", "body": {{ "breakpoints": [{}] }} }})",
      seq, fmt::join(serialized_bkpts, ","));
}

ui::UICommand *
parse_command(Command cmd, nlohmann::json &&args) noexcept
{
  switch (cmd) {
  case Command::Attach:
  case Command::BreakpointLocations:
  case Command::Completions:
  case Command::ConfigurationDone:
    break;
  case Command::Continue: {
    const auto all_threads = !args.contains("singleThread") ? true : false;
    return new ui::dap::Continue{args.at("threadId"), all_threads};
  }
  case Command::CustomRequest:
  case Command::DataBreakpointInfo:
  case Command::Disassemble:
  case Command::Disconnect:
  case Command::Evaluate:
  case Command::ExceptionInfo:
  case Command::Goto:
  case Command::GotoTargets:
  case Command::Initialize:
  case Command::Launch:
  case Command::LoadedSources:
  case Command::Modules:
  case Command::Next:
  case Command::Pause:
  case Command::ReadMemory:
  case Command::Restart:
  case Command::RestartFrame:
  case Command::ReverseContinue:
  case Command::Scopes:
  case Command::SetBreakpoints:
  case Command::SetDataBreakpoints:
  case Command::SetExceptionBreakpoints:
  case Command::SetExpression:
  case Command::SetFunctionBreakpoints:
    break;
  case Command::SetInstructionBreakpoints: {
    return new ui::dap::SetInstructionBreakpoints{std::move(args)};
  }
  case Command::SetVariable:
  case Command::Source:
  case Command::StackTrace:
  case Command::StepBack:
  case Command::StepIn:
  case Command::StepInTargets:
  case Command::StepOut:
  case Command::Terminate:
  case Command::TerminateThreads:
  case Command::Threads:
  case Command::Variables:
  case Command::WriteMemory:
  case Command::UNKNOWN:
    break;
  }
  PANIC("Could not parse command");
  return nullptr;
}

} // namespace ui::dap