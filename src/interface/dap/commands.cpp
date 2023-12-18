#include "commands.h"
#include "fmt/format.h"
#include "nlohmann/json_fwd.hpp"
#include "parse_buffer.h"
#include "types.h"
#include <algorithm>
#include <iterator>
#include <memory>
#include <optional>
#include <ptracestop_handlers.h>
#include <string>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <tracer.h>
#include <unistd.h>
#include <unordered_set>
#include <utils/base64.h>
#include <valarray>

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
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": false, "command": "continue", "message": "notStopped" }})",
        seq, response_seq);
}

UIResultPtr
Continue::execute(Tracer *tracer) noexcept
{
  auto res = new ContinueResponse{true, this};
  res->continue_all = continue_all;
  auto target = tracer->get_current();
  if (continue_all && target->is_running()) {
    std::vector<Tid> running_tasks{};
    for (const auto &t : target->threads) {
      if (!t.is_stopped() || t.tracer_stopped)
        running_tasks.push_back(t.tid);
    }
    DLOG("mdb", "Denying continue request, target is running ([{}])", fmt::join(running_tasks, ", "));
    res->success = false;
  } else {
    res->success = true;
    if (continue_all) {
      DLOG("mdb", "[request:continue]: continue all");
      target->resume_target(RunType::Continue);
    } else {
      DLOG("mdb", "[request:continue]: continue single thread: {}", thread_id);
      auto t = target->get_task(thread_id);
      target->resume_task(t, RunType::Continue);
    }
  }

  return res;
}

std::string
NextResponse::serialize(int seq) const noexcept
{
  if (success)
    return fmt::format(
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "next" }})", seq,
        response_seq);
  else
    return fmt::format(
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": false, "command": "next", "message": "notStopped" }})",
        seq, response_seq);
}

UIResultPtr
Next::execute(Tracer *tracer) noexcept
{
  auto target = tracer->get_current();
  auto task = target->get_task(thread_id);

  if (!task->is_stopped()) {
    return new NextResponse{false, this};
  }

  switch (granularity) {
  case SteppingGranularity::Instruction:
    DLOG("mdb", "Stepping task {} 1 instruction, starting at {:x}", thread_id, task->registers->rip);
    target->install_ptracestop_handler<ptracestop::InstructionStep>(task->tid, !continue_all, task, 1);
    break;
  case SteppingGranularity::Line:
    target->install_ptracestop_handler<ptracestop::LineStep>(task->tid, !continue_all, task, 1);
    break;
  case SteppingGranularity::LogicalBreakpointLocation:
    TODO("Next::execute granularity=SteppingGranularity::LogicalBreakpointLocation")
    break;
  }
  return new NextResponse{true, this};
}

std::string
StepOutResponse::serialize(int seq) const noexcept
{
  if (success)
    return fmt::format(
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "stepOut" }})", seq,
        response_seq);
  else
    return fmt::format(
        R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": false, "command": "stepOut", "message": "notStopped" }})",
        seq, response_seq);
}

UIResultPtr
StepOut::execute(Tracer *tracer) noexcept
{
  TODO("StepOut::execute");
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
    switch (this->type) {
    case BreakpointType::Source:
      return fmt::format(
          R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "setBreakpoints", "body": {{ "breakpoints": [{}] }} }})",
          seq, response_seq, fmt::join(serialized_bkpts, ","));
    case BreakpointType::Function:
      return fmt::format(
          R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "setFunctionBreakpoints", "body": {{ "breakpoints": [{}] }} }})",
          seq, response_seq, fmt::join(serialized_bkpts, ","));
    case BreakpointType::Address:
      return fmt::format(
          R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "setInstructionBreakpoints", "body": {{ "breakpoints": [{}] }} }})",
          seq, response_seq, fmt::join(serialized_bkpts, ","));
      break;
    default:
      PANIC("DAP doesn't expect Tracer breakpoints");
    }
  } else {
    TODO("Unsuccessful set instruction breakpoints event response handling");
  }
}

SetBreakpoints::SetBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept
    : ui::UICommand(seq), args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetBreakpoints::execute(Tracer *tracer) noexcept
{
  auto res = new SetBreakpointsResponse{true, this, BreakpointType::Source};
  auto target = tracer->get_current();
  ASSERT(args.contains("source"), "setBreakpoints request requires a 'source' field");
  ASSERT(args.at("source").contains("path"), "source field requires a 'path' field");
  std::string file = args["source"]["path"];
  const auto source_file = target->get_source(file);
  std::vector<SourceBreakpointDescriptor> src_bps;
  if (source_file.has_value()) {
    for (const auto &src_bp : args.at("breakpoints")) {
      ASSERT(src_bp.contains("line"), "Source breakpoint requires a 'line' field");
      u32 line = src_bp["line"];
      std::optional<u32> col = std::nullopt;
      std::optional<std::string> condition = std::nullopt;
      std::optional<int> hit_condition = std::nullopt;
      std::optional<std::string> log_message = std::nullopt;

      if (src_bp.contains("column")) {
        col = src_bp["column"];
      }
      if (src_bp.contains("condition")) {
        condition = src_bp["condition"];
      }
      if (src_bp.contains("hitCondition")) {
        hit_condition = src_bp["hitCondition"];
      }
      if (src_bp.contains("logMessage")) {
        log_message = std::make_optional(src_bp["logMessage"]);
      }
      src_bps.push_back(
          SourceBreakpointDescriptor{*source_file, line, col, condition, hit_condition, log_message});
    }
    target->reset_source_breakpoints(*source_file, std::move(src_bps));
    using BP = ui::dap::Breakpoint;
    for (const auto &bp : target->bps.breakpoints) {
      if (bp.type().source && target->bps.source_breakpoints[bp.id].source_file == *source_file) {
        const auto &description = target->bps.source_breakpoints[bp.id];
        res->breakpoints.push_back(BP{.id = bp.id,
                                      .verified = true,
                                      .addr = bp.address,
                                      .line = description.line,
                                      .col = description.column,
                                      .source_path = description.source_file});
      }
    }
  } else {
    using BP = ui::dap::Breakpoint;
    const auto count = args.at("breakpoints").size();
    for (auto i = 1000u; i < count + 1000u; i++) {
      res->breakpoints.push_back(BP{.id = i,
                                    .verified = false,
                                    .addr = nullptr,
                                    .line = std::nullopt,
                                    .col = std::nullopt,
                                    .source_path = std::nullopt,
                                    .error_message = "Could not find source file"});
    }
  }
  return res;
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

  auto res = new SetBreakpointsResponse{true, this, BreakpointType::Address};
  res->breakpoints.reserve(target->bps.breakpoints.size());

  for (const auto &bp : target->bps.breakpoints) {
    if (bp.type().address) {
      res->breakpoints.push_back(BP{
          .id = bp.id,
          .verified = true,
          .addr = bp.address,
          .line = std::nullopt,
          .col = std::nullopt,
          .source_path = std::nullopt,
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
  auto res = new SetBreakpointsResponse{true, this, BreakpointType::Function};
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

  for (const auto &bp : target->bps.breakpoints) {
    if (bp.type().function) {
      res->breakpoints.push_back(BP{
          .id = bp.id,
          .verified = true,
          .addr = bp.address,
          .line = std::nullopt,
          .col = std::nullopt,
          .source_path = std::nullopt,
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

ReadMemory::ReadMemory(std::uint64_t seq, AddrPtr address, int offset, u64 bytes) noexcept
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
  tracer->config_done();
  return new ConfigurationDoneResponse{true, this};
}

Initialize::Initialize(std::uint64_t seq, nlohmann::json &&arguments) noexcept
    : UICommand(seq), args(std::move(arguments))
{
}

UIResultPtr
Initialize::execute(Tracer *) noexcept
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
  tracer->disconnect();
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
  cfg_body["supportsDisassembleRequest"] = true;
  cfg_body["supportsCancelRequest"] = false;
  cfg_body["supportsBreakpointLocationsRequest"] = false;
  cfg_body["supportsClipboardContext"] = false;
  cfg_body["supportsSteppingGranularity"] = false;
  cfg_body["supportsInstructionBreakpoints"] = true;
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

Launch::Launch(std::uint64_t seq, bool stopAtEntry, Path &&program,
               std::vector<std::string> &&program_args) noexcept
    : UICommand(seq), stopAtEntry(stopAtEntry), program(std::move(program)), program_args(std::move(program_args))
{
}

UIResultPtr
Launch::execute(Tracer *tracer) noexcept
{
  tracer->launch(stopAtEntry, std::move(program), std::move(program_args));
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

  response->threads.reserve(target->threads.size());
  for (const auto &thread : target->threads) {
    response->threads.push_back(Thread{.id = thread.tid, .name = target->get_thread_name(thread.tid)});
  }
  return response;
}

StackTrace::StackTrace(std::uint64_t seq, int threadId, std::optional<int> startFrame, std::optional<int> levels,
                       std::optional<StackTraceFormat> format) noexcept
    : UICommand(seq), threadId(threadId), startFrame(startFrame), levels(levels), format(format)
{
}

StackTraceResponse::StackTraceResponse(bool success, StackTrace *cmd,
                                       std::vector<StackFrame> &&stack_frames) noexcept
    : UIResult(success, cmd), stack_frames(std::move(stack_frames))
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
  if (task == nullptr) {
    TODO(fmt::format("Handle not-found thread by threadId {}", threadId));
  }
  auto &cfs = target->build_callframe_stack(task, CallStackRequest::full());

  std::vector<StackFrame> stack_frames{};
  stack_frames.reserve(cfs.frames.size());
  for (const auto &frame : cfs.frames) {
    if (frame.type == sym::FrameType::Full) {
      const auto lt = frame.symbol->decl_file->get_linetable().value_or(sym::dw::LineTable{});

      auto line = 0;
      auto col = 0;
      if (lt.is_valid()) {
        // todo(simon): linear search is horrid. But binary search is so fragile instead. So for now, we do the
        // absolute worst, so long it works.
        auto iter_count = 0u;
        const auto end = std::end(lt);
        for (auto ita = std::begin(lt), itb = ita + 1; ita != end && itb != end; ++ita, ++itb) {
          if ((*ita).pc <= frame.rip && (*itb).pc > frame.rip) {
            line = (*ita).line;
            col = (*ita).column;
            break;
          }
          if constexpr (MDB_DEBUG == 1) {
            ++iter_count;
            ASSERT(iter_count <= lt.size(), "Iterated beyond table size");
          }
        }
        stack_frames.push_back(StackFrame{
            .id = frame.frame_id,
            .name = frame.name().value_or("unknown"),
            .source = Source{.name = frame.symbol->decl_file->name(), .path = frame.symbol->decl_file->name()},
            .line = line,
            .column = col,
            .rip = fmt::format("{}", frame.rip)});
      }
    } else {
      stack_frames.push_back(StackFrame{.id = frame.frame_id,
                                        .name = frame.name().value_or("unknown"),
                                        .source = std::nullopt,
                                        .line = 0,
                                        .column = 0,
                                        .rip = fmt::format("{}", frame.rip)});
    }
  }
  return new StackTraceResponse{true, this, std::move(stack_frames)};
}

Scopes::Scopes(std::uint64_t seq, int frameId) noexcept : UICommand(seq), frameId(frameId) {}

std::string
ScopesResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "scopes", "body": {{ "scopes": [{}] }} }})",
      seq, response_seq, fmt::join(scopes, ","));
}

ScopesResponse::ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept
    : UIResult(success, cmd), scopes(scopes)
{
}

UIResultPtr
Scopes::execute(Tracer *tracer) noexcept
{
  auto current = tracer->get_current();
  return new ScopesResponse{true, this, current->scopes_reference(frameId)};
}

Disassemble::Disassemble(std::uint64_t seq, AddrPtr address, int byte_offset, int ins_offset, int ins_count,
                         bool resolve_symbols) noexcept
    : UICommand(seq), address(address), byte_offset(byte_offset), ins_offset(ins_offset), ins_count(ins_count),
      resolve_symbols(resolve_symbols)
{
}

UIResultPtr
Disassemble::execute(Tracer *tracer) noexcept
{
  auto res = new DisassembleResponse{true, this};
  res->instructions.reserve(ins_count);
  int remaining = ins_count;
  if (ins_offset < 0) {
    const int negative_offset = std::abs(ins_offset);
    sym::zydis_disasm_backwards(tracer->get_current(), address, static_cast<u32>(negative_offset),
                                res->instructions);
    if (negative_offset < ins_count) {
      for (auto i = 0u; i < res->instructions.size(); i++) {
        if (res->instructions[i].address == address) {
          keep_range(res->instructions, i - negative_offset, i);
          break;
        }
      }
    } else {
      for (auto i = 0u; i < res->instructions.size(); i++) {
        if (res->instructions[i].address == address) {
          keep_range(res->instructions, i - negative_offset, i - negative_offset + ins_count);
          break;
        }
      }
      return res;
    }
    remaining -= res->instructions.size();
    ins_offset = 0;
  }

  if (remaining > 0) {
    sym::zydis_disasm(tracer->get_current(), address, static_cast<u32>(std::abs(ins_offset)), remaining,
                      res->instructions);
  }
  return res;
}

std::string
DisassembleResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "disassemble", "body": {{ "instructions": [{}] }} }})",
      seq, response_seq, fmt::join(instructions, ","));
}

Variables::Variables(std::uint64_t seq, int var_ref) noexcept : UICommand(seq), var_ref(var_ref) {}

UIResultPtr
Variables::execute(Tracer *tracer) noexcept
{
  DLOG("mdb", "[dap cmd]: variables command returns an empty list for now");
  auto current = tracer->get_current();
  if (const auto varref = current->var_ref(this->var_ref); varref) {
    const auto frame_id = varref->frame_id;
    const auto frame = current->frame(frame_id);
    DLOG("mdb", "Get variables for frame {}", *frame);
    return new VariablesResponse{true, this, {}};
  } else {
    return new VariablesResponse{false, this, {}};
  }
}

VariablesResponse::VariablesResponse(bool success, Variables *cmd, std::vector<Variable> &&vars) noexcept
    : UIResult(success, cmd), variables(std::move(vars))
{
}

std::string
VariablesResponse::serialize(int seq) const noexcept
{
  return fmt::format(
      R"({{ "seq": {}, "response_seq": {}, "type": "response", "success": true, "command": "variables", "body": {{ "variables": [{}] }} }})",
      seq, response_seq, fmt::join(variables, ","));
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
  case CommandType::Disassemble: {
    ASSERT(args.contains("memoryReference"), "Args did not contain 'memoryReference'");
    ASSERT(args.contains("offset"), "Args did not contain 'offset'");
    ASSERT(args.contains("instructionCount"), "Args did not contain 'instructionCount'");
    ASSERT(args.contains("instructionOffset"), "Args did not contain 'instructionOffset'");
    std::string_view addr_str;
    args["memoryReference"].get_to(addr_str);
    const auto addr = to_addr(addr_str);
    int offset = args.at("offset");
    int instructionOffset = args.at("instructionOffset");
    int instructionCount = args.at("instructionCount");
    return new ui::dap::Disassemble{seq, *addr, offset, instructionOffset, instructionCount, false};
  }
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
    const bool stopAtEntry = args.contains("stopAtEntry");
    return new Launch{seq, stopAtEntry, std::move(path), std::move(prog_args)};
  }
  case CommandType::LoadedSources:
    TODO("Command::LoadedSources");
  case CommandType::Modules:
    TODO("Command::Modules");
  case CommandType::Next: {
    ASSERT(args.contains("threadId"),
           "Next requests must contain a threadId whether or not all-stop is the execution mode");
    int thread_id = args["threadId"];
    bool single_thread = false;
    SteppingGranularity step_type = SteppingGranularity::Line;
    if (args.contains("granularity")) {
      std::string_view str_arg;
      args["granularity"].get_to(str_arg);
      step_type = from_str(str_arg);
    }
    if (args.contains("singleThread")) {
      single_thread = args["singleThread"];
    }
    return new Next{seq, thread_id, !single_thread, step_type};
  }
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
  case CommandType::Scopes: {
    const int frame_id = args.at("frameId");
    return new ui::dap::Scopes{seq, frame_id};
  }
  case CommandType::SetBreakpoints:
    return new SetBreakpoints{seq, std::move(args)};
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
  case CommandType::Variables: {
    int var_ref = args["variablesReference"];
    return new Variables{seq, var_ref};
  }
  case CommandType::WriteMemory:
    TODO("Command::WriteMemory");
  case CommandType::UNKNOWN:
    break;
  }
  PANIC("Could not parse command");
  return nullptr;
}

} // namespace ui::dap