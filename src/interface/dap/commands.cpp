#include "commands.h"
#include "../../target.h"
#include "../../tracer.h"
#include "../../utils/base64.h"
#include "fmt/format.h"
#include "nlohmann/json_fwd.hpp"
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
        R"({{ "response_seq": {}, "type": "response", "success": true, "command": "continue", "body": {{ "allThreadsContinued": {} }} }})",
        seq, continue_all);
  else
    return fmt::format(
        R"({{ "response_seq": {}, "type": "response", "success": false, "command": "continue", "message": "notStopped" }})",
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
        R"({{ "response_seq": {}, "type": "response", "success": true, "command": "setBreakpoints", "body": {{ "breakpoints": [{}] }} }})",
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

std::string
ReadMemoryResponse::serialize(int seq) const noexcept
{
  if (success) {
    return fmt::format(
        R"({{ "response_seq": {}, "type": "response", "success": true, "command": "readMemory", "body": {{ "address": {}, "unreadableBytes": {}, "data": {} }} }})",
        seq, first_readable_address, unreadable_bytes, data_base64);
  } else {
    TODO("non-success for ReadMemory");
  }
}

ReadMemory::ReadMemory(TPtr<void> address, int offset, u64 bytes) noexcept
    : address(address), offset(offset), bytes(bytes)
{
}

UIResultPtr
ReadMemory::execute(Tracer *tracer) noexcept
{
  auto sv = tracer->get_current()->read_to_vector(address, bytes);
  auto res = new ReadMemoryResponse{};
  res->data_base64 = utils::encode_base64(sv->span());
  res->first_readable_address = address;
  res->success = true;
  res->unreadable_bytes = 0;
  return res;
}

std::string
ConfigurationDoneResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "response_seq": {}, "type": "response", "success": true, "command": "configurationDone" }})", seq);
}

Initialize::Initialize(nlohmann::json &&arguments) noexcept : args(std::move(arguments)) {}

UIResultPtr
Initialize::execute(Tracer *tracer) noexcept
{
  return new InitializeResponse{};
}

std::string
InitializeResponse::serialize(int seq) const noexcept
{
  // "this _must_ be 1, the first response"

  nlohmann::json cfg;
  auto &cfg_body = cfg["body"];
  cfg_body["supportsConfigurationDoneRequest"] = true;
  cfg_body["supportsFunctionBreakpoints"] = true;
  cfg_body["supportsConditionalBreakpoints"] = false;
  cfg_body["supportsHitConditionalBreakpoints"] = true;
  cfg_body["supportsEvaluateForHovers"] = false;
  // cfg_body["exceptionBreakpointFilters"] = []
  cfg_body["supportsStepBack"] = false;
  cfg_body["supportsSetVariable"] = false;
  cfg_body["supportsRestartFrame"] = false;
  cfg_body["supportsGotoTargetsRequest"] = false;
  cfg_body["supportsStepInTargetsRequest"] = false;
  cfg_body["supportsCompletionsRequest"] = true;
  cfg_body["completionTriggerCharacters"] = {".", "["};
  cfg_body["supportsModulesRequest"] = false;
  cfg_body["additionalModuleColumns"] = false;
  cfg_body["supportedChecksumAlgorithms"] = false;
  cfg_body["supportsRestartRequest"] = false;
  cfg_body["supportsExceptionOptions"] = false;
  cfg_body["supportsValueFormattingOptions"] = true;
  cfg_body["supportsExceptionInfoRequest"] = true;
  cfg_body["supportTerminateDebuggee"] = true;
  cfg_body["supportSuspendDebuggee"] = false;
  cfg_body["supportsDelayedStackTraceLoading"] = false;
  cfg_body["supportsLoadedSourcesRequest"] = false;
  cfg_body["supportsLogPoints"] = false;
  cfg_body["supportsTerminateThreadsRequest"] = true;
  cfg_body["supportsSetExpression"] = false;
  cfg_body["supportsTerminateRequest"] = true;
  cfg_body["supportsDataBreakpoints"] = false;
  cfg_body["supportsReadMemoryRequest"] = true;
  cfg_body["supportsWriteMemoryRequest"] = false;
  cfg_body["supportsDisassembleRequest"] = false;
  cfg_body["supportsCancelRequest"] = false;
  cfg_body["supportsBreakpointLocationsRequest"] = false;
  cfg_body["supportsClipboardContext"] = false;
  cfg_body["supportsSteppingGranularity"] = false;
  cfg_body["supportsInstructionBreakpoints"] = false;
  cfg_body["supportsExceptionFilterOptions"] = false;
  cfg_body["supportsSingleThreadExecutionRequests"] = false;

  return fmt::format(
      R"({{ "response_seq": 1, "type": "response", "success": true, "command": "initialize", "body": {} }})", seq,
      cfg_body.dump());
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
    return new ConfigurationDone{};
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
    return new Initialize{std::move(args)};
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
  case Command::ReadMemory: {
    ASSERT(args.contains("memoryReference") && args.contains("count"),
           "args didn't contain memoryReference or count");
    std::string_view addr_str;
    args.at("instructionReference").get_to(addr_str);
    auto addr = to_addr(addr_str);
    auto offset = 0;
    if (args.contains("offset")) {
      offset = args.at("offset");
    }
    u64 count = args.at("count");
    return new ui::dap::ReadMemory{*addr, offset, count};
  }
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
    return new SetFunctionBreakpoints{std::move(args)};
  case Command::SetInstructionBreakpoints:
    return new SetInstructionBreakpoints{std::move(args)};
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