#include "commands.h"
#include "../../target.h"
#include "../../tracer.h"
#include "../../utils/base64.h"
#include "fmt/format.h"
#include "nlohmann/json_fwd.hpp"
#include "parse_buffer.h"
#include "types.h"
#include <algorithm>
#include <memory>
#include <optional>
#include <ranges>
#include <unistd.h>
#include <unordered_set>
namespace ui::dap {

std::string
ContinueResponse::serialize(int seq) const noexcept
{

  if (success)
    return fmt::format(
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "continue", "body": {{ "allThreadsContinued": {} }} }})",
        seq, response_seq, continue_all);
  else
    return fmt::format(
        R"({{ "seq": {} "response_seq": {}, "type": "response", "success": false, "command": "continue", "message": "notStopped" }})",
        seq, response_seq);
}

UIResultPtr
Continue::execute(Tracer *tracer) noexcept
{
  auto res = new ContinueResponse{true, this};
  res->continue_all = continue_all;
  auto target = tracer->get_current();
  if (target->is_running()) {
    res->success = false;
  } else {
    res->success = true;
    target->resume_target(RunType::Continue);
  }

  return res;
}

SetBreakpointsResponse::SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointType type) noexcept
    : ui::UIResult(success, cmd), type(type), breakpoints()
{
}

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
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "setBreakpoints", "body": {{ "breakpoints": [{}] }} }})",
        seq, response_seq, fmt::join(serialized_bkpts, ","));
  } else {
    TODO("Unsuccessful set instruction breakpoints event response handling");
  }
}

SetInstructionBreakpoints::SetInstructionBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept
    : UICommand(seq), args(std::move(arguments))
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

  auto res = new SetBreakpointsResponse{true, this, BreakpointType::AddressBreakpoint};
  res->breakpoints.reserve(target->user_brkpts.breakpoints.size());

  for (const auto &bp : target->user_brkpts.breakpoints) {
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

SetFunctionBreakpoints::SetFunctionBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept
    : UICommand(seq), args(std::move(arguments))
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

  auto res = new SetBreakpointsResponse{true, this, BreakpointType::FunctionBreakpoint};
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

  for (const auto &bp : target->user_brkpts.breakpoints) {
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
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "readMemory", "body": {{ "address": "{}", "unreadableBytes": {}, "data": "{}" }} }})",
        seq, response_seq, first_readable_address, unreadable_bytes, data_base64);
  } else {
    TODO("non-success for ReadMemory");
  }
}

ReadMemory::ReadMemory(std::uint64_t seq, TPtr<void> address, int offset, u64 bytes) noexcept
    : UICommand(seq), address(address), offset(offset), bytes(bytes)
{
}

UIResultPtr
ReadMemory::execute(Tracer *tracer) noexcept
{
  auto sv = tracer->get_current()->read_to_vector(address, bytes);
  auto res = new ReadMemoryResponse{true, this};
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
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "configurationDone" }})",
      seq, response_seq);
}

UIResultPtr
ConfigurationDone::execute(Tracer *tracer) noexcept
{
  tracer->get_current()->resume_target(RunType::Continue);
  tracer->get_current()->start_awaiter_thread();
  return new ConfigurationDoneResponse{true, this};
}

Initialize::Initialize(std::uint64_t seq, nlohmann::json &&arguments) noexcept
    : UICommand(seq), args(std::move(arguments))
{
}

UIResultPtr
Initialize::execute(Tracer *tracer) noexcept
{
  return new InitializeResponse{true, this};
}

std::string
DisconnectResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "disconnect" }})", seq,
      response_seq);
}

Disconnect::Disconnect(std::uint64_t seq, bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept
    : UICommand(seq), restart(restart), terminate_tracee(terminate_debuggee), suspend_tracee(suspend_debuggee)
{
}
UIResultPtr
Disconnect::execute(Tracer *tracer) noexcept
{
  tracer->kill_all_targets();
  return new DisconnectResponse{true, this};
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
      R"({{ "response_seq": {}, "type": "response", "success": true, "command": "initialize", "body": {} }})", seq,
      cfg_body.dump());
}

std::string
LaunchResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "launch" }})", seq,
      response_seq);
}

Launch::Launch(std::uint64_t seq, Path &&program, std::vector<std::string> &&program_args) noexcept
    : UICommand(seq), program(std::move(program)), program_args(std::move(program_args))
{
}

UIResultPtr
Launch::execute(Tracer *tracer) noexcept
{
  tracer->launch(std::move(program), std::move(program_args));
  return new LaunchResponse{true, this};
}

std::string
TerminateResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "terminate" }})", seq,
      response_seq);
}

UIResultPtr
Terminate::execute(Tracer *tracer) noexcept
{
  bool success = tracer->get_current()->terminate_gracefully();
  return new TerminateResponse{success, this};
}

std::string
ThreadsResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "threads", "body": {{ "threads": [{}] }} }})",
      seq, response_seq, fmt::join(threads, ","));
}

UIResultPtr
Threads::execute(Tracer *tracer) noexcept
{
  // todo(simon): right now, we only support 1 process, but theoretically the current design
  // allows for more; it would require some work to get the DAP protocol to play nicely though.
  // therefore we just hand back the threads of the currently active target
  auto response = new ThreadsResponse{true, this};
  const auto target = tracer->get_current();

  const auto &threads = target->threads;
  response->threads.reserve(threads.size());
  for (auto thread : threads) {
    response->threads.push_back(Thread{.id = thread.tid, .name = target->get_thread_name(thread.tid)});
  }
  return response;
}

StackTrace::StackTrace(std::uint64_t seq, int threadId, std::optional<int> startFrame, std::optional<int> levels,
                       std::optional<StackTraceFormat> format) noexcept
    : UICommand(seq), threadId(threadId), startFrame(startFrame), levels(levels), format(format)
{
}

std::string
StackTraceResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "stackTrace", "body": {{ "stackFrames": [{}] }} }})",
      seq, response_seq, fmt::join(stack_frames, ","));
}

UIResultPtr
StackTrace::execute(Tracer *tracer) noexcept
{
  // todo(simon): multiprocessing needs additional work, since DAP does not support it natively.
  auto target = tracer->get_current();
  auto task = target->get_task(threadId);
  auto &cfs = target->build_callframe_stack(task);
  auto response = new StackTraceResponse{true, this};
  response->stack_frames.reserve(cfs.frames.size());
  auto id = 1;
  for (const auto &frame : cfs.frames) {
    if (frame.type == sym::FrameType::Full) {
      auto &lt = frame.cu_file->line_table();
      auto line = 0;
      auto col = 0;
      for (auto ita = lt.cbegin(), itb = ita + 1; ita != lt.cend() && itb != lt.cend(); ita++, itb++) {
        if (ita->pc <= frame.rip && itb->pc >= frame.rip) {
          line = ita->line;
          col = ita->column;
        }
      }
      response->stack_frames.push_back(
          StackFrame{.id = id++,
                     .name = frame.fn_name.value_or("unknown"),
                     .source = Source{.name = frame.cu_file->name(), .path = frame.cu_file->name()},
                     .line = line,
                     .column = col,
                     .rip = fmt::format("{}", frame.rip)});
    } else {
      response->stack_frames.push_back(StackFrame{.id = id++,
                                                  .name = frame.fn_name.value_or("unknown"),
                                                  .source = std::nullopt,
                                                  .line = 0,
                                                  .column = 0,
                                                  .rip = fmt::format("{}", frame.rip)});
    }
  }
  return response;
}

ui::UICommand *
parse_command(std::string &&packet) noexcept
{
  auto obj = nlohmann::json::parse(packet, nullptr, false);
  std::string_view cmd_name;
  obj["command"].get_to(cmd_name);
  ASSERT(obj.contains("arguments"), "Request did not contain an 'arguments' field: {}", packet);
  const u64 seq = obj["seq"];
  const auto cmd = parse_command_type(cmd_name);
  auto &&args = std::move(obj["arguments"]);
  switch (cmd) {
  case CommandType::Attach:
    TODO("Command::Attach");
  case CommandType::BreakpointLocations:
    TODO("Command::BreakpointLocations");
  case CommandType::Completions:
    TODO("Command::Completions");
  case CommandType::ConfigurationDone:
    return new ConfigurationDone{seq};
    break;
  case CommandType::Continue: {
    const auto all_threads = !args.contains("singleThread") ? true : false;
    return new ui::dap::Continue{seq, args.at("threadId"), all_threads};
  }
  case CommandType::CustomRequest:
    TODO("Command::CustomRequest");
  case CommandType::DataBreakpointInfo:
    TODO("Command::DataBreakpointInfo");
  case CommandType::Disassemble:
    TODO("Command::Disassemble");
  case CommandType::Disconnect: {
    bool restart = false;
    bool terminate_debuggee = false;
    bool suspend_debuggee = false;
    if (args.contains("restart")) {
      restart = args.at("restart");
    }
    if (args.contains("terminateDebuggee")) {
      terminate_debuggee = args.at("terminateDebuggee");
    }
    if (args.contains("suspendDebuggee")) {
      suspend_debuggee = args.at("suspendDebuggee");
    }
    return new Disconnect{seq, restart, terminate_debuggee, suspend_debuggee};
  }
  case CommandType::Evaluate:
    TODO("Command::Evaluate");
  case CommandType::ExceptionInfo:
    TODO("Command::ExceptionInfo");
  case CommandType::Goto:
    TODO("Command::Goto");
  case CommandType::GotoTargets:
    TODO("Command::GotoTargets");
  case CommandType::Initialize:
    return new Initialize{seq, std::move(args)};
  case CommandType::Launch: {
    ASSERT(args.contains("program"), "Launch must contain 'program' field in args");
    Path path = args.at("program");
    std::vector<std::string> prog_args;
    if (args.contains("args")) {
      prog_args = args.at("args");
    }
    return new Launch{seq, std::move(path), std::move(prog_args)};
  }
  case CommandType::LoadedSources:
    TODO("Command::LoadedSources");
  case CommandType::Modules:
    TODO("Command::Modules");
  case CommandType::Next:
    TODO("Command::Next");
  case CommandType::Pause:
    TODO("Command::Pause");
  case CommandType::ReadMemory: {
    ASSERT(args.contains("memoryReference") && args.contains("count"),
           "args didn't contain memoryReference or count");
    std::string_view addr_str;
    args.at("memoryReference").get_to(addr_str);
    const auto addr = to_addr(addr_str);
    const auto offset = args.value("offset", 0);
    const u64 count = args.at("count");
    return new ui::dap::ReadMemory{seq, *addr, offset, count};
  }
  case CommandType::Restart:
    TODO("Command::Restart");
  case CommandType::RestartFrame:
    TODO("Command::RestartFrame");
  case CommandType::ReverseContinue:
    TODO("Command::ReverseContinue");
  case CommandType::Scopes:
    TODO("Command::Scopes");
  case CommandType::SetBreakpoints:
    TODO("Command::SetBreakpoints");
  case CommandType::SetDataBreakpoints:
    TODO("Command::SetDataBreakpoints");
  case CommandType::SetExceptionBreakpoints:
    TODO("Command::SetExceptionBreakpoints");
  case CommandType::SetExpression:
    TODO("Command::SetExpression");
  case CommandType::SetFunctionBreakpoints:
    return new SetFunctionBreakpoints{seq, std::move(args)};
  case CommandType::SetInstructionBreakpoints:
    return new SetInstructionBreakpoints{seq, std::move(args)};
  case CommandType::SetVariable:
    TODO("Command::SetVariable");
  case CommandType::Source:
    TODO("Command::Source");
  case CommandType::StackTrace: {
    std::optional<int> startFrame;
    std::optional<int> levels;
    std::optional<StackTraceFormat> format_;
    if (args.contains("startFrame")) {
      startFrame = args.at("startFrame");
    }
    if (args.contains("levels")) {
      levels = args.at("levels");
    }
    if (args.contains("format")) {
      auto &fmt = args["format"];
      StackTraceFormat format;
      format.parameters = fmt.value("parameters", true);
      format.parameterTypes = fmt.value("parameterTypes", true);
      format.parameterNames = fmt.value("parameterNames", true);
      format.parameterValues = fmt.value("parameterValues", true);
      format.line = fmt.value("line", true);
      format.module = fmt.value("module", false);
      format.includeAll = fmt.value("includeAll", true);
      format_ = format;
    }
    return new ui::dap::StackTrace{seq, args.at("threadId"), startFrame, levels, format_};
  }
  case CommandType::StepBack:
    TODO("Command::StepBack");
  case CommandType::StepIn:
    TODO("Command::StepIn");
  case CommandType::StepInTargets:
    TODO("Command::StepInTargets");
  case CommandType::StepOut:
    TODO("Command::StepOut");
  case CommandType::Terminate:
    return new Terminate{seq};
  case CommandType::TerminateThreads:
    TODO("Command::TerminateThreads");
  case CommandType::Threads:
    return new Threads{seq};
  case CommandType::Variables:
    TODO("Command::Variables");
  case CommandType::WriteMemory:
    TODO("Command::WriteMemory");
  case CommandType::UNKNOWN:
    break;
  }
  PANIC("Could not parse command");
  return nullptr;
}

} // namespace ui::dap