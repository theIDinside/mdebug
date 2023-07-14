#include "commands.h"
#include "../../target.h"
#include "../../tracer.h"
#include "fmt/format.h"
#include "types.h"
#include <algorithm>
#include <memory>
#include <ranges>
#include <unordered_set>
namespace ui::dap {

std::string
ContinueResponse::serialize(int seq) const noexcept
{
  if (success)
    return fmt::format(
        R"({{ "seq": {}, "type": "response", "success": true, "command": "continue", "body": {{ "allThreadsContinued": {} }} }})",
        seq, continue_all);
  else
    return fmt::format(
        R"({{ "seq": {}, "type": "response", "success": false, "command": "continue", "message": "notStopped" }})",
        seq);
}

UIResultPtr
Continue::execute(Tracer *tracer) noexcept
{
  auto res = new ContinueResponse{};
  res->continue_all = continue_all;
  auto target = tracer->get_current();
  if (target->is_running()) {
    res->success = false;
  } else {
    res->success = true;
    target->set_all_running(RunType::Continue);
  }

  return res;
}

SetBreakpointsResponse::SetBreakpointsResponse(BreakpointType type) noexcept : type(type), breakpoints() {}

std::string
SetBreakpointsResponse::serialize(int seq) const noexcept
{
  if (success) {
    std::vector<std::string> serialized_bkpts{};
    serialized_bkpts.reserve(breakpoints.size());
    for (auto &bp : breakpoints) {
      serialized_bkpts.push_back(bp.serialize());
    }
    return fmt::format(
        R"({{ "seq": {}, "type": "response", "success": true, "command": "continue", "body": {{ "breakpoints": [{}] }} }})",
        seq, fmt::join(serialized_bkpts, ","));
  } else {
    TODO("Unsuccessful set instruction breakpoints event response handling");
  }
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
  target->reset_addr_breakpoints(addresses);

  auto res = new SetBreakpointsResponse{BreakpointType::AddressBreakpoint};
  res->breakpoints.reserve(target->user_breakpoints_map.breakpoints.size());

  for (const auto &bp : target->user_breakpoints_map.breakpoints) {
    if (bp.type == BreakpointType::AddressBreakpoint) {
      res->breakpoints.push_back(BP{
          .id = bp.bp_id,
          .verified = true,
          .addr = bp.address,
      });
    }
  }
  ASSERT(res->breakpoints.size() == addresses.size(), "Response value size does not match result size");
  res->success = true;

  return res;
}

SetFunctionBreakpoints::SetFunctionBreakpoints(nlohmann::json &&arguments) noexcept : args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetFunctionBreakpoints::execute(Tracer *tracer) noexcept
{
  using BP = ui::dap::Breakpoint;
  std::vector<std::string_view> bkpts{};
  std::vector<std::string_view> new_ones{};

  auto res = new SetBreakpointsResponse{BreakpointType::FunctionBreakpoint};
  for (const auto &fnbkpt : args.at("breakpoints")) {
    ASSERT(fnbkpt.contains("name") && fnbkpt["name"].is_string(),
           "instructionReference field not in args or wasn't of type string");
    std::string_view fn_name;
    fnbkpt["name"].get_to(fn_name);
    ASSERT(!fn_name.empty(), "Couldn't parse fn name from fn breakpoint request");
    bkpts.push_back(fn_name);
  }
  auto target = tracer->get_current();
  target->reset_fn_breakpoints(bkpts);

  for (const auto &bp : target->user_breakpoints_map.breakpoints) {
    if (bp.type == BreakpointType::FunctionBreakpoint) {
      res->breakpoints.push_back(BP{
          .id = bp.bp_id,
          .verified = true,
          .addr = bp.address,
      });
    }
  }
  res->success = true;
  return res;
}

ui::UICommand *
parse_command(Command cmd, nlohmann::json &&args) noexcept
{
  switch (cmd) {
  case Command::Attach:
    TODO("Command::Attach");
  case Command::BreakpointLocations:
    TODO("Command::BreakpointLocations");
  case Command::Completions:
    TODO("Command::Completions");
  case Command::ConfigurationDone:
    TODO("Command::ConfigurationDone");
    break;
  case Command::Continue: {
    const auto all_threads = !args.contains("singleThread") ? true : false;
    return new ui::dap::Continue{args.at("threadId"), all_threads};
  }
  case Command::CustomRequest:
    TODO("Command::CustomRequest");
  case Command::DataBreakpointInfo:
    TODO("Command::DataBreakpointInfo");
  case Command::Disassemble:
    TODO("Command::Disassemble");
  case Command::Disconnect:
    TODO("Command::Disconnect")
  case Command::Evaluate:
    TODO("Command::Evaluate");
  case Command::ExceptionInfo:
    TODO("Command::ExceptionInfo");
  case Command::Goto:
    TODO("Command::Goto");
  case Command::GotoTargets:
    TODO("Command::GotoTargets");
  case Command::Initialize:
    TODO("Command::Initialize");
  case Command::Launch:
    TODO("Command::Launch");
  case Command::LoadedSources:
    TODO("Command::LoadedSources");
  case Command::Modules:
    TODO("Command::Modules");
  case Command::Next:
    TODO("Command::Next");
  case Command::Pause:
    TODO("Command::Pause");
  case Command::ReadMemory:
    TODO("Command::ReadMemory");
  case Command::Restart:
    TODO("Command::Restart");
  case Command::RestartFrame:
    TODO("Command::RestartFrame");
  case Command::ReverseContinue:
    TODO("Command::ReverseContinue");
  case Command::Scopes:
    TODO("Command::Scopes");
  case Command::SetBreakpoints:
    TODO("Command::SetBreakpoints");
  case Command::SetDataBreakpoints:
    TODO("Command::SetDataBreakpoints");
  case Command::SetExceptionBreakpoints:
    TODO("Command::SetExceptionBreakpoints");
  case Command::SetExpression:
    TODO("Command::SetExpression");
  case Command::SetFunctionBreakpoints:
    return new ui::dap::SetFunctionBreakpoints{std::move(args)};
  case Command::SetInstructionBreakpoints:
    return new ui::dap::SetInstructionBreakpoints{std::move(args)};
  case Command::SetVariable:
    TODO("Command::SetVariable");
  case Command::Source:
    TODO("Command::Source");
  case Command::StackTrace:
    TODO("Command::StackTrace");
  case Command::StepBack:
    TODO("Command::StepBack");
  case Command::StepIn:
    TODO("Command::StepIn");
  case Command::StepInTargets:
    TODO("Command::StepInTargets");
  case Command::StepOut:
    TODO("Command::StepOut");
  case Command::Terminate:
    TODO("Command::Terminate");
  case Command::TerminateThreads:
    TODO("Command::TerminateThreads");
  case Command::Threads:
    TODO("Command::Threads");
  case Command::Variables:
    TODO("Command::Variables");
  case Command::WriteMemory:
    TODO("Command::WriteMemory");
  case Command::UNKNOWN:
    break;
  }
  PANIC("Could not parse command");
  return nullptr;
}

} // namespace ui::dap