#include "commands.h"
#include "bp.h"
#include "common.h"
#include "events/event.h"
#include "interface/attach_args.h"
#include "interface/dap/events.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "interface/ui_command.h"
#include "parse_buffer.h"
#include "symbolication/callstack.h"
#include "types.h"
#include "utils/expected.h"
#include "utils/logger.h"
#include <algorithm>
#include <fmt/core.h>
#include <fmt/format.h>
#include <interface/dap/interface.h>
#include <memory>
#include <optional>
#include <ptracestop_handlers.h>
#include <string>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <tracer.h>
#include <unordered_set>
#include <utils/base64.h>

namespace ui::dap {

template <typename Res, typename JsonObj>
inline std::optional<Res>
get(const JsonObj &obj, std::string_view field)
{
  if (obj.contains(field)) {
    return obj[field];
  }
  return std::nullopt;
}

static constexpr SteppingGranularity
from_str(std::string_view granularity) noexcept
{
  if (granularity == "statement") {
    return SteppingGranularity::LogicalBreakpointLocation; // default
  } else if (granularity == "line") {
    return SteppingGranularity::Line; // default
  } else if (granularity == "instruction") {
    return SteppingGranularity::Instruction; // default
  } else {
    return SteppingGranularity::Line; // default
  }
}

ErrorResponse::ErrorResponse(std::string_view command, ui::UICommandPtr cmd,
                             std::optional<std::string> &&short_message, std::optional<Message> &&message) noexcept
    : ui::UIResult(false, cmd), command(command), short_message(std::move(short_message)),
      message(std::move(message))
{
}

std::string
ErrorResponse::serialize(int seq) const noexcept
{
  if (short_message && message) {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}","body":{{ "error":{}}}}})",
      seq, request_seq, command, *short_message, *message);
  } else if (short_message && !message) {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}"}})", seq,
      request_seq, command, *short_message);
  } else if (!short_message && message) {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","body":{{"error":{}}}}})",
      seq, request_seq, command, *message);
  } else {
    return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}"}})", seq,
                       request_seq, command);
  }
}

std::string
PauseResponse::serialize(int seq) const noexcept
{
  if (success) {
    return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"pause"}})", seq,
                       request_seq);
  } else {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"pause","message":"taskwasnotrunning"}})",
      seq, request_seq);
  }
}

UIResultPtr
Pause::execute(Tracer *tc) noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->get_task(pauseArgs.threadId);
  if (task->is_stopped()) {
    return new PauseResponse{false, this};
  }
  target->install_thread_proceed<ptracestop::StopImmediately>(*task, StoppedReason::Pause);
  return new PauseResponse{true, this};
}

std::string
ContinueResponse::serialize(int seq) const noexcept
{

  if (success) {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"continue","body":{{"allThreadsContinued":{}}}}})",
      seq, request_seq, continue_all);
  } else {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"continue","message":"notStopped"}})",
      seq, request_seq);
  }
}

UIResultPtr
Continue::execute(Tracer *tracer) noexcept
{
  auto res = new ContinueResponse{true, this};
  res->continue_all = continue_all;
  auto target = dap_client->supervisor();
  if (continue_all && target->is_running()) {
    std::vector<Tid> running_tasks{};
    for (const auto &t : target->threads) {
      if (!t.is_stopped() || t.tracer_stopped) {
        running_tasks.push_back(t.tid);
      }
    }
    DBGLOG(core, "Denying continue request, target is running ([{}])", fmt::join(running_tasks, ", "));
    res->success = false;
  } else {
    res->success = true;
    if (continue_all) {
      DBGLOG(core, "continue all");
      target->resume_target(tc::RunType::Continue);
    } else {
      DBGLOG(core, "continue single thread: {}", thread_id);
      auto t = target->get_task(thread_id);
      target->resume_task(*t, {tc::RunType::Continue, tc::ResumeTarget::Task});
    }
  }

  return res;
}

std::string
NextResponse::serialize(int seq) const noexcept
{
  if (success) {
    return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"next"}})", seq,
                       request_seq);
  } else {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"next","message":"notStopped"}})",
      seq, request_seq);
  }
}

UIResultPtr
Next::execute(Tracer *tracer) noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->get_task(thread_id);

  if (!task->is_stopped()) {
    return new NextResponse{false, this};
  }

  switch (granularity) {
  case SteppingGranularity::Instruction:
    DBGLOG(core, "Stepping task {} 1 instruction, starting at {:x}", thread_id, task->get_pc());
    target->install_thread_proceed<ptracestop::InstructionStep>(*task, 1);
    break;
  case SteppingGranularity::Line:
    target->install_thread_proceed<ptracestop::LineStep>(*task, 1);
    break;
  case SteppingGranularity::LogicalBreakpointLocation:
    TODO("Next::execute granularity=SteppingGranularity::LogicalBreakpointLocation")
    break;
  }
  return new NextResponse{true, this};
}

std::string
StepInResponse::serialize(int seq) const noexcept
{
  if (success) {
    return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"stepIn"}})", seq,
                       request_seq);
  } else {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"stepIn","message":"notStopped"}})",
      seq, request_seq);
  }
}

UIResultPtr
StepIn::execute(Tracer *tracer) noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->get_task(thread_id);

  if (!task->is_stopped()) {
    return new StepInResponse{false, this};
  }

  auto proceeder = ptracestop::StepInto::create(*target, *task);

  if (!proceeder) {
    return new ErrorResponse{
      Request, this,
      std::make_optional("No line table information could be found - abstract stepping not possible."),
      std::nullopt};
  }

  target->set_and_run_action(task->tid, proceeder);
  return new StepInResponse{true, this};
}

std::string
StepOutResponse::serialize(int seq) const noexcept
{
  if (success) {
    return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"stepOut"}})",
                       seq, request_seq);
  } else {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"stepOut","message":"notStopped"}})",
      seq, request_seq);
  }
}

UIResultPtr
StepOut::execute(Tracer *tracer) noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->get_task(thread_id);

  if (!task->is_stopped()) {
    return new StepOutResponse{false, this};
  }
  const auto req = CallStackRequest::partial(2);
  auto resume_addrs = task->return_addresses(target, req);
  ASSERT(resume_addrs.size() >= req.count, "Could not find frame info");
  const auto rip = resume_addrs[1];
  auto loc = target->get_or_create_bp_location(rip, false);
  if (!loc.is_expected()) {
    return new StepOutResponse{false, this};
  }
  auto user = target->pbps.create_loc_user<FinishBreakpoint>(*target, std::move(loc), task->tid, task->tid);
  target->install_thread_proceed<ptracestop::FinishFunction>(*task, user, false);
  return new StepOutResponse{true, this};
}

SetBreakpointsResponse::SetBreakpointsResponse(bool success, ui::UICommandPtr cmd,
                                               BreakpointRequestKind type) noexcept
    : ui::UIResult(success, cmd), type(type), breakpoints()
{
}

std::string
SetBreakpointsResponse::serialize(int seq) const noexcept
{
  std::vector<std::string> serialized_bkpts{};
  serialized_bkpts.reserve(breakpoints.size());
  for (auto &bp : breakpoints) {
    serialized_bkpts.push_back(bp.serialize());
  }
  switch (this->type) {
  case BreakpointRequestKind::source:
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"setBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, fmt::join(serialized_bkpts, ","));
  case BreakpointRequestKind::function:
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"setFunctionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, fmt::join(serialized_bkpts, ","));
  case BreakpointRequestKind::instruction:
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"setInstructionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::exception:
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"setExceptionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, success, fmt::join(serialized_bkpts, ","));
    break;
  default:
    PANIC("DAP doesn't expect Tracer breakpoints");
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
  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::source};
  auto target = dap_client->supervisor();
  if (!target) {
    return res;
  }

  ASSERT(args.contains("source"), "setBreakpoints request requires a 'source' field");
  ASSERT(args.at("source").contains("path"), "source field requires a 'path' field");
  const std::string file = args["source"]["path"];
  Set<SourceBreakpointSpec> src_bps;
  for (const auto &src_bp : args.at("breakpoints")) {
    ASSERT(src_bp.contains("line"), "Source breakpoint requires a 'line' field");
    const u32 line = src_bp["line"];
    src_bps.insert(SourceBreakpointSpec{line, get<u32>(src_bp, "column"), get<std::string>(src_bp, "condition"),
                                        get<std::string>(src_bp, "logMessage")});
  }

  target->set_source_breakpoints(file, src_bps);

  using BP = ui::dap::Breakpoint;

  for (const auto &[bp, ids] : target->pbps.bps_for_source(file)) {
    for (const auto id : ids) {
      const auto user = target->pbps.get_user(id);
      res->breakpoints.push_back(BP::from_user_bp(user));
    }
  }

  return res;
}

SetExceptionBreakpoints::SetExceptionBreakpoints(std::uint64_t sequence, nlohmann::json &&args) noexcept
    : ui::UICommand{sequence}, args(std::move(args))
{
}

UIResultPtr
SetExceptionBreakpoints::execute(Tracer *tracer) noexcept
{
  DBGLOG(core, "{:p} exception breakpoints not yet implemented", (void *)tracer);
  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::exception};
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
  Set<InstructionBreakpointSpec> bps{};
  const auto ibps = args.at("breakpoints");
  for (const auto &ibkpt : ibps) {
    ASSERT(ibkpt.contains("instructionReference") && ibkpt["instructionReference"].is_string(),
           "instructionReference field not in args or wasn't of type string");
    std::string_view addr_str;
    ibkpt["instructionReference"].get_to(addr_str);
    bps.insert(InstructionBreakpointSpec{.instructionReference = std::string{addr_str}, .condition = {}});
  }
  auto target = dap_client->supervisor();
  target->set_instruction_breakpoints(bps);

  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::instruction};
  res->breakpoints.reserve(target->pbps.instruction_breakpoints.size());

  for (const auto &[k, id] : target->pbps.instruction_breakpoints) {
    res->breakpoints.push_back(BP::from_user_bp(target->pbps.get_user(id)));
  }

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
  Set<FunctionBreakpointSpec> bkpts{};
  std::vector<std::string_view> new_ones{};
  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::function};
  for (const auto &fnbkpt : args.at("breakpoints")) {
    ASSERT(fnbkpt.contains("name") && fnbkpt["name"].is_string(),
           "instructionReference field not in args or wasn't of type string");
    std::string fn_name = fnbkpt["name"];
    bool is_regex = false;
    if (fnbkpt.contains("regex")) {
      is_regex = fnbkpt["regex"];
    }

    bkpts.insert(FunctionBreakpointSpec{fn_name, std::nullopt, is_regex});
  }
  auto target = dap_client->supervisor();

  target->set_fn_breakpoints(bkpts);
  for (const auto &user : target->pbps.all_users()) {
    if (user->kind == LocationUserKind::Function) {
      res->breakpoints.push_back(BP::from_user_bp(user));
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
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"readMemory","body":{{"address":"{}","unreadableBytes":{},"data":"{}"}}}})",
      seq, request_seq, first_readable_address, unreadable_bytes, data_base64);
  } else {
    TODO("non-success for ReadMemory");
  }
}

ReadMemory::ReadMemory(std::uint64_t seq, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept
    : UICommand(seq), address(address), offset(offset), bytes(bytes)
{
}

UIResultPtr
ReadMemory::execute(Tracer *tracer) noexcept
{
  if (address) {
    auto sv = dap_client->supervisor()->read_to_vector(*address, bytes);
    auto res = new ReadMemoryResponse{true, this};
    res->data_base64 = utils::encode_base64(sv->span());
    res->first_readable_address = *address;
    res->success = true;
    res->unreadable_bytes = 0;
    return res;
  } else {
    return new ErrorResponse{Request, this, "Address parameter could not be parsed.", std::nullopt};
  }
}

std::string
ConfigurationDoneResponse::serialize(int seq) const noexcept
{
  return fmt::format(
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"configurationDone"}})", seq,
    request_seq);
}

UIResultPtr
ConfigurationDone::execute(Tracer *tracer) noexcept
{
  tracer->config_done(dap_client);
  switch (dap_client->supervisor()->session_type()) {
  case TargetSession::Launched:
    dap_client->supervisor()->resume_target(tc::RunType::Continue);
    break;
  case TargetSession::Attached:
    break;
  }

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
  return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"disconnect"}})",
                     seq, request_seq);
}

Disconnect::Disconnect(std::uint64_t seq, bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept
    : UICommand(seq), restart(restart), terminate_tracee(terminate_debuggee), suspend_tracee(suspend_debuggee)
{
}
UIResultPtr
Disconnect::execute(Tracer *tracer) noexcept
{
  auto ok = tracer->disconnect(dap_client, true);
  dap_client->post_event(new TerminatedEvent{});
  return new DisconnectResponse{ok, this};
}

std::string
InitializeResponse::serialize(int seq) const noexcept
{
  // "this _must_ be 1, the first response"

  nlohmann::json cfg;
  auto &cfg_body = cfg["body"];
  std::array<nlohmann::json, 3> arrs{};
  arrs[0] =
    nlohmann::json::object({{"filter", "throw"}, {"label", "Thrown exceptions"}, {"supportsCondition", false}});
  arrs[1] = nlohmann::json::object(
    {{"filter", "rethrow"}, {"label", "Re-thrown exceptions"}, {"supportsCondition", false}});
  arrs[2] =
    nlohmann::json::object({{"filter", "catch"}, {"label", "Caught exceptions"}, {"supportsCondition", false}});

  cfg_body["supportsConfigurationDoneRequest"] = true;
  cfg_body["supportsFunctionBreakpoints"] = true;
  cfg_body["supportsConditionalBreakpoints"] = false;
  cfg_body["supportsHitConditionalBreakpoints"] = true;
  cfg_body["supportsEvaluateForHovers"] = false;
  // cfg_body["exceptionBreakpointFilters"] = std::array<nlohmann::json, 0>{};
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
  cfg_body["supportsExceptionInfoRequest"] = false;
  cfg_body["supportTerminateDebuggee"] = true;
  cfg_body["supportSuspendDebuggee"] = false;
  cfg_body["supportsDelayedStackTraceLoading"] = false;
  cfg_body["supportsLoadedSourcesRequest"] = false;
  cfg_body["supportsLogPoints"] = false;
  cfg_body["supportsTerminateThreadsRequest"] = true;
  cfg_body["supportsVariableType"] = true;
  cfg_body["supportsSetExpression"] = false;
  cfg_body["supportsTerminateRequest"] = true;
  cfg_body["supportsDataBreakpoints"] = false;
  cfg_body["supportsReadMemoryRequest"] = true;
  cfg_body["supportsWriteMemoryRequest"] = false;
  cfg_body["supportsDisassembleRequest"] = true;
  cfg_body["supportsCancelRequest"] = false;
  cfg_body["supportsBreakpointLocationsRequest"] = false;
  cfg_body["supportsSteppingGranularity"] = true;
  cfg_body["supportsInstructionBreakpoints"] = true;
  cfg_body["supportsExceptionFilterOptions"] = false;
  cfg_body["supportsSingleThreadExecutionRequests"] = true;

  auto payload = fmt::format(
    R"({{"seq":0,"request_seq":{},"type":"response","success":true,"command":"initialize","body":{}}})",
    request_seq, cfg_body.dump());

  client->write(payload);
  client->write(InitializedEvent{}.serialize(0));
  return "";
}

std::string
LaunchResponse::serialize(int seq) const noexcept
{
  return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"launch"}})", seq,
                     request_seq);
}

Launch::Launch(std::uint64_t seq, bool stopOnEntry, Path &&program,
               std::vector<std::string> &&program_args) noexcept
    : UICommand(seq), stopOnEntry(stopOnEntry), program(std::move(program)), program_args(std::move(program_args))
{
}

UIResultPtr
Launch::execute(Tracer *tracer) noexcept
{
  tracer->launch(dap_client, stopOnEntry, std::move(program), std::move(program_args));
  return new LaunchResponse{true, this};
}

std::string
AttachResponse::serialize(int seq) const noexcept
{
  return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"attach"}})", seq,
                     request_seq);
}

Attach::Attach(std::uint64_t seq, AttachArgs &&args) noexcept : UICommand(seq), attachArgs(std::move(args)) {}

UIResultPtr
Attach::execute(Tracer *tracer) noexcept
{
  const auto res = tracer->attach(attachArgs);
  return new AttachResponse{res, this};
}

std::string
TerminateResponse::serialize(int seq) const noexcept
{
  return fmt::format(R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"terminate"}})",
                     seq, request_seq);
}

UIResultPtr
Terminate::execute(Tracer *tracer) noexcept
{
  auto ok = tracer->disconnect(dap_client, true);
  dap_client->post_event(new TerminatedEvent{});
  return new TerminateResponse{ok, this};
}

std::string
ThreadsResponse::serialize(int seq) const noexcept
{
  return fmt::format(
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"threads","body":{{"threads":[{}]}}}})",
    seq, request_seq, fmt::join(threads, ","));
}

UIResultPtr
Threads::execute(Tracer *tracer) noexcept
{
  // todo(simon): right now, we only support 1 process, but theoretically the current design
  // allows for more; it would require some work to get the DAP protocol to play nicely though.
  // therefore we just hand back the threads of the currently active target
  auto response = new ThreadsResponse{true, this};

  auto target = dap_client->supervisor();

  response->threads.reserve(target->threads.size());
  auto &it = target->get_interface();
  for (const auto &thread : target->threads) {
    response->threads.push_back(Thread{.id = thread.tid, .name = it.get_thread_name(thread.tid)});
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
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"stackTrace","body":{{"stackFrames":[{}]}}}})",
    seq, request_seq, fmt::join(stack_frames, ","));
}

constexpr bool
is_debug_build()
{
  if constexpr (MDB_DEBUG == 0) {
    return false;
  } else {
    return true;
  }
}

UIResultPtr
StackTrace::execute(Tracer *tracer) noexcept
{
  // todo(simon): multiprocessing needs additional work, since DAP does not support it natively.
  auto target = dap_client->supervisor();
  auto task = target->get_task(threadId);
  if (task == nullptr) {
    return new ErrorResponse{StackTrace::Request, this, fmt::format("Thread with ID {} not found", threadId), {}};
  }
  auto &cfs = target->build_callframe_stack(*task, CallStackRequest::full());

  std::vector<StackFrame> stack_frames{};
  stack_frames.reserve(cfs.frames.size());
  for (const auto &frame : cfs.frames) {
    if (frame.frame_type() == sym::FrameType::Full) {
      const auto lt = frame.cu_line_table().value_or(sym::dw::LineTable{});

      auto line = 0;
      auto col = 0;
      if (lt.is_valid()) {
        // todo(simon): linear search is horrid. But binary search is so fragile instead. So for now, we do the
        // absolute worst, so long it works.
        const auto fpc = frame.pc();
        const auto end = std::end(lt);
        for (auto ita = std::begin(lt), itb = ita + 1; ita != end && itb != end; ++ita, ++itb) {
          if ((*ita).pc <= fpc && (*itb).pc > fpc) {
            line = (*ita).line;
            col = (*ita).column;
            break;
          }
        }
        // todo(simon): Source {name, path} should consist of what it says, {name, path}, not {path, path}
        const auto src = frame.full_symbol_info().symbol_info()->name();
        stack_frames.push_back(StackFrame{.id = frame.id(),
                                          .name = frame.name().value_or("unknown"),
                                          .source = Source{.name = src, .path = src},
                                          .line = line,
                                          .column = col,
                                          .rip = fmt::format("{}", fpc)});
      }
    } else {
      stack_frames.push_back(StackFrame{.id = frame.id(),
                                        .name = frame.name().value_or("unknown"),
                                        .source = std::nullopt,
                                        .line = 0,
                                        .column = 0,
                                        .rip = fmt::format("{}", frame.pc())});
    }
  }
  return new StackTraceResponse{true, this, std::move(stack_frames)};
}

Scopes::Scopes(std::uint64_t seq, int frameId) noexcept : UICommand(seq), frameId(frameId) {}

std::string
ScopesResponse::serialize(int seq) const noexcept
{
  return fmt::format(
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"scopes","body":{{"scopes":[{}]}}}})",
    seq, request_seq, fmt::join(scopes, ","));
}

ScopesResponse::ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept
    : UIResult(success, cmd), scopes(scopes)
{
}

UIResultPtr
Scopes::execute(Tracer *tracer) noexcept
{
  auto ctx = tracer->var_context(frameId);
  if (!ctx.valid_context() || ctx.type != ContextType::Frame) {
    return new ErrorResponse{Request, this, fmt::format("Invalid variable context for {}", frameId), {}};
  }
  auto frame = ctx.get_frame(frameId);
  if (!frame) {
    return new ScopesResponse{false, this, {}};
  }
  const auto scopes = frame->scopes();
  return new ScopesResponse{true, this, scopes};
}

Disassemble::Disassemble(std::uint64_t seq, std::optional<AddrPtr> address, int byte_offset, int ins_offset,
                         int ins_count, bool resolve_symbols) noexcept
    : UICommand(seq), address(address), byte_offset(byte_offset), ins_offset(ins_offset), ins_count(ins_count),
      resolve_symbols(resolve_symbols)
{
}

UIResultPtr
Disassemble::execute(Tracer *tracer) noexcept
{
  if (address) {
    auto res = new DisassembleResponse{true, this};
    res->instructions.reserve(ins_count);
    int remaining = ins_count;
    if (ins_offset < 0) {
      const int negative_offset = std::abs(ins_offset);
      sym::zydis_disasm_backwards(dap_client->supervisor(), address.value(), static_cast<u32>(negative_offset),
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
      sym::zydis_disasm(dap_client->supervisor(), address.value(), static_cast<u32>(std::abs(ins_offset)),
                        remaining, res->instructions);
    }
    return res;
  } else {
    return new ErrorResponse{Request, this, "Address parameter could not be parsed.", std::nullopt};
  }
}

std::string
DisassembleResponse::serialize(int seq) const noexcept
{
  return fmt::format(
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"disassemble","body":{{"instructions":[{}]}}}})",
    seq, request_seq, fmt::join(instructions, ","));
}

Evaluate::Evaluate(u64 seq, std::string &&expression, std::optional<int> frameId,
                   std::optional<EvaluationContext> context) noexcept
    : UICommand(seq), expr(std::move(expression)), frameId(frameId),
      context(context.value_or(EvaluationContext::Watch))
{
}

UIResultPtr
Evaluate::execute(Tracer *tracer) noexcept
{
  return new ErrorResponse{Request, this, {}, Message{.format = "could not evaluate"}};
}

std::optional<EvaluationContext>
Evaluate::parse_context(std::string_view input) noexcept
{

  static constexpr auto contexts = {
    std::pair{"watch", EvaluationContext::Watch}, std::pair{"repl", EvaluationContext::Repl},
    std::pair{"hover", EvaluationContext::Hover}, std::pair{"clipboard", EvaluationContext::Clipboard},
    std::pair{"variables", EvaluationContext::Variables}};

  for (const auto &[k, v] : contexts) {
    if (k == input) {
      return v;
    }
  }
  return {};
}

EvaluateResponse::EvaluateResponse(bool success, Evaluate *cmd, std::optional<int> variablesReference,
                                   std::string &&result, std::optional<std::string> &&type,
                                   std::optional<std::string> &&memoryReference) noexcept
    : UIResult(success, cmd), result(std::move(result)), type(std::move(type)),
      variablesReference(variablesReference.value_or(0)), memoryReference(std::move(memoryReference))
{
}

std::string
EvaluateResponse::serialize(int seq) const noexcept
{
  if (success) {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"evaluate","body":{{ "result":"{}", "variablesReference":{} }}}})",
      seq, request_seq, success, result, variablesReference);
  } else {
    return fmt::format(
      R"({{"seq":0,"request_seq":{},"type":"response","success":false,"command":"evaluate","body":{{ "error":{{ "id": -1, "format": "{}" }} }}}})",
      request_seq, success, result);
  }
}

Variables::Variables(std::uint64_t seq, int var_ref, std::optional<u32> start, std::optional<u32> count) noexcept
    : UICommand(seq), var_ref(var_ref), start(start), count(count)
{
}

ErrorResponse *
Variables::error(std::string &&msg) noexcept
{
  return new ErrorResponse{
    Request, this, {}, Message{.format = std::move(msg), .variables = {}, .show_user = true}};
}

UIResultPtr
Variables::execute(Tracer *tracer) noexcept
{
  auto context = tracer->var_context(var_ref);
  if (!context.valid_context()) {
    return error(fmt::format("Could not find variable with variablesReference {}", var_ref));
  }
  auto frame = context.get_frame(var_ref);
  if (!frame) {
    return error(fmt::format("Could not find frame that's referenced via variablesReference {}", var_ref));
  }

  switch (context.type) {
  case ContextType::Frame:
    return error(fmt::format("Sent a variables request using a reference for a frame is an error.", var_ref));
  case ContextType::Scope: {
    auto scope = frame->scope(var_ref);
    switch (scope->type) {
    case ScopeType::Arguments: {
      auto vars = context.symbol_file->getVariables(*context.tc, *frame, sym::VariableSet::Arguments);
      return new VariablesResponse{true, this, std::move(vars)};
    }
    case ScopeType::Locals: {
      auto vars = context.symbol_file->getVariables(*context.tc, *frame, sym::VariableSet::Locals);
      return new VariablesResponse{true, this, std::move(vars)};
    }
    case ScopeType::Registers: {
      return new VariablesResponse{true, this, {}};
    } break;
    }
  } break;
  case ContextType::Variable:
    return new VariablesResponse{true, this, context.symbol_file->resolve(context, start, count)};
  case ContextType::Global:
    TODO("Global variables not yet implemented support for");
    break;
  }

  return error(fmt::format("Could not find variable with variablesReference {}", var_ref));
}

VariablesResponse::VariablesResponse(bool success, Variables *cmd, std::vector<Variable> &&vars) noexcept
    : UIResult(success, cmd), requested_reference(cmd != nullptr ? cmd->var_ref : 0), variables(std::move(vars))
{
}

std::string
VariablesResponse::serialize(int seq) const noexcept
{
  if (variables.empty()) {
    return fmt::format(
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"variables","body":{{"variables":[]}}}})",
      seq, request_seq);
  }
  std::string variables_contents{};
  auto it = std::back_inserter(variables_contents);
  for (const auto &v : variables) {
    if (auto datvis = v.variable_value->get_visualizer(); datvis != nullptr) {
      auto opt = datvis->dap_format(v.variable_value->name, v.ref);
      if (opt) {
        it = fmt::format_to(it, "{},", *opt);
      } else {
        return fmt::format(
          R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"variables","message":"visualizer failed","body":{{"error":{{"id": -1, "format": "Could not visualize value for '{}'"}} }} }})",
          seq, request_seq, v.variable_value->name);
      }
    } else {
      ASSERT(v.variable_value->type()->is_reference(), "Add visualizer & resolver for T* types. It will look more "
                                                       "or less identical to CStringResolver & ArrayResolver");
      // Todo: this seem particularly shitty. For many reasons. First we check if there's a visualizer, then we
      // do individual type checking again.
      //  this should be streamlined, to be handled once up front. We also need some way to create "new" types.
      auto span = v.variable_value->memory_view();
      const std::uintptr_t ptr = sym::bit_copy<std::uintptr_t>(span);
      auto ptr_str = fmt::format("0x{:x}", ptr);
      it = fmt::format_to(
        it,
        R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }},)",
        v.variable_value->name, ptr_str, *v.variable_value->type(), v.ref, v.variable_value->address());
    }
  }

  variables_contents.pop_back();
  return fmt::format(
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"variables","body":{{"variables":[{}]}}}})",
    seq, request_seq, variables_contents);
}

InvalidArgs::InvalidArgs(std::uint64_t seq, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
    : UICommand(seq), command(command), missing_arguments(std::move(missing_args))
{
}

UIResultPtr
InvalidArgs::execute(Tracer *) noexcept
{
  return new InvalidArgsResponse{command, std::move(missing_arguments)};
}

InvalidArgsResponse::InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
    : command(command), missing_or_invalid(std::move(missing_args))
{
}

std::string
InvalidArgsResponse::serialize(int seq) const noexcept
{
  std::vector<std::string_view> missing{};
  std::vector<const InvalidArg *> parsed_and_invalid{};
  missing.reserve(missing_or_invalid.size());
  for (const auto &pair : missing_or_invalid) {
    const auto &[k, v] = pair;
    switch (k.kind) {
    case ArgumentErrorKind::Missing:
      missing.push_back(v);
      break;
    case ArgumentErrorKind::InvalidInput:
      parsed_and_invalid.push_back(&pair);
      break;
    }
  }

  std::array<char, 1024> message{};
  auto it = !missing.empty() ? fmt::format_to(message.begin(), "Missing arguments: {}. ", fmt::join(missing, ", "))
                             : message.begin();

  std::array<char, 1024> invals{};
  if (!parsed_and_invalid.empty()) {
    decltype(fmt::format_to(invals.begin(), "")) inv_it;
    for (auto ref : parsed_and_invalid) {
      if (ref->first.description) {
        inv_it = fmt::format_to(invals.begin(), "{}: {}\\n", ref->second, ref->first.description.value());
      } else {
        inv_it = fmt::format_to(invals.begin(), "{}\\n", ref->second);
      }
    }

    it = fmt::format_to(it, "Invalid input for: {}", std::string_view{invals.begin(), inv_it});
  }
  *it = 0;
  std::string_view msg{message.begin(), message.begin() + std::distance(message.begin(), it)};

  return fmt::format(
    R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}"}})", seq,
    request_seq, command, msg);
}

#define IfInvalidArgsReturn(type)                                                                                 \
  if (const auto missing = Validate<type>(seq, args); missing) {                                                  \
    return missing;                                                                                               \
  }

ui::UICommand *
parse_command(std::string &&packet) noexcept
{
  using namespace ui::dap;

  auto obj = nlohmann::json::parse(packet, nullptr, false);
  std::string_view cmd_name;
  const std::string req = obj.dump();
  DBGLOG(core, "parsed request: {}", req);
  obj["command"].get_to(cmd_name);
  ASSERT(obj.contains("arguments"), "Request did not contain an 'arguments' field: {}", packet);
  const u64 seq = obj["seq"];
  const auto cmd = parse_command_type(cmd_name);
  auto &&args = std::move(obj["arguments"]);
  switch (cmd) {
  case CommandType::Attach: {
    IfInvalidArgsReturn(Attach);
    return Attach::create(seq, args);
  }
  case CommandType::BreakpointLocations:
    TODO("Command::BreakpointLocations");
  case CommandType::Completions:
    TODO("Command::Completions");
  case CommandType::ConfigurationDone:
    return new ConfigurationDone{seq};
    break;
  case CommandType::Continue: {
    IfInvalidArgsReturn(Continue);

    const auto all_threads = !args.contains("singleThread") ? true : false;
    return new Continue{seq, args.at("threadId"), all_threads};
  }
  case CommandType::CustomRequest:
    TODO("Command::CustomRequest");
  case CommandType::DataBreakpointInfo:
    TODO("Command::DataBreakpointInfo");
  case CommandType::Disassemble: {
    IfInvalidArgsReturn(Disassemble);

    std::string_view addr_str;
    args["memoryReference"].get_to(addr_str);
    const auto addr = to_addr(addr_str);
    int offset = args.at("offset");
    int instructionOffset = args.at("instructionOffset");
    int instructionCount = args.at("instructionCount");
    return new ui::dap::Disassemble{seq, addr, offset, instructionOffset, instructionCount, false};
  }
  case CommandType::Disconnect: {
    IfInvalidArgsReturn(Disconnect);

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
  case CommandType::Evaluate: {
    IfInvalidArgsReturn(Evaluate);

    std::string expr = args.at("expression");
    std::optional<int> frameId{};
    std::optional<EvaluationContext> ctx{};

    if (args.contains("frameId")) {
      const auto &ref = args.at("frameId");
      if (ref.is_number()) {
        frameId = args.at("frameId");
      }
    }

    if (args.contains("context")) {
      const auto &ref = args.at("context");
      if (ref.is_string()) {
        std::string_view context;
        ref.get_to(context);
        ctx = Evaluate::parse_context(context);
      }
    }

    return new ui::dap::Evaluate{seq, std::move(expr), frameId, ctx};
  }
  case CommandType::ExceptionInfo:
    TODO("Command::ExceptionInfo");
  case CommandType::Goto:
    TODO("Command::Goto");
  case CommandType::GotoTargets:
    TODO("Command::GotoTargets");
  case CommandType::Initialize:
    return new Initialize{seq, std::move(args)};
  case CommandType::Launch: {
    IfInvalidArgsReturn(Launch);

    Path path = args.at("program");
    std::vector<std::string> prog_args;
    if (args.contains("args")) {
      prog_args = args.at("args");
    }
    const bool stopOnEntry = args.contains("stopOnEntry");
    return new Launch{seq, stopOnEntry, std::move(path), std::move(prog_args)};
  }
  case CommandType::LoadedSources:
    TODO("Command::LoadedSources");
  case CommandType::Modules:
    TODO("Command::Modules");
  case CommandType::Next: {
    IfInvalidArgsReturn(Next);

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
  case CommandType::Pause: {
    IfInvalidArgsReturn(Pause);

    int thread_id = args["threadId"];
    return new Pause(seq, Pause::Args{thread_id});
  }
  case CommandType::ReadMemory: {
    IfInvalidArgsReturn(ReadMemory);

    std::string_view addr_str;
    args.at("memoryReference").get_to(addr_str);
    const auto addr = to_addr(addr_str);
    const auto offset = args.value("offset", 0);
    const u64 count = args.at("count");
    return new ui::dap::ReadMemory{seq, addr, offset, count};
  }
  case CommandType::Restart:
    TODO("Command::Restart");
  case CommandType::RestartFrame:
    TODO("Command::RestartFrame");
  case CommandType::ReverseContinue:
    TODO("Command::ReverseContinue");
  case CommandType::Scopes: {
    IfInvalidArgsReturn(Scopes);

    const int frame_id = args.at("frameId");
    return new ui::dap::Scopes{seq, frame_id};
  }
  case CommandType::SetBreakpoints:
    IfInvalidArgsReturn(SetBreakpoints);

    return new SetBreakpoints{seq, std::move(args)};
  case CommandType::SetDataBreakpoints:
    TODO("Command::SetDataBreakpoints");
  case CommandType::SetExceptionBreakpoints: {
    IfInvalidArgsReturn(SetExceptionBreakpoints);
    return new SetExceptionBreakpoints{seq, std::move(args)};
  }
  case CommandType::SetExpression:
    TODO("Command::SetExpression");
  case CommandType::SetFunctionBreakpoints:
    IfInvalidArgsReturn(SetFunctionBreakpoints);

    return new SetFunctionBreakpoints{seq, std::move(args)};
  case CommandType::SetInstructionBreakpoints:
    IfInvalidArgsReturn(SetInstructionBreakpoints);

    return new SetInstructionBreakpoints{seq, std::move(args)};
  case CommandType::SetVariable:
    TODO("Command::SetVariable");
  case CommandType::Source:
    TODO("Command::Source");
  case CommandType::StackTrace: {
    IfInvalidArgsReturn(StackTrace);

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
  case CommandType::StepIn: {
    IfInvalidArgsReturn(StepIn);

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

    return new StepIn{seq, thread_id, single_thread, step_type};
  }
  case CommandType::StepInTargets:
    TODO("Command::StepInTargets");
  case CommandType::StepOut: {
    IfInvalidArgsReturn(StepOut);

    int thread_id = args["threadId"];
    bool single_thread = false;
    if (args.contains("singleThread")) {
      single_thread = args["singleThread"];
    }
    return new ui::dap::StepOut{seq, thread_id, !single_thread};
  }
  case CommandType::Terminate:
    IfInvalidArgsReturn(Terminate);

    return new Terminate{seq};
  case CommandType::TerminateThreads:
    TODO("Command::TerminateThreads");
  case CommandType::Threads:
    IfInvalidArgsReturn(Threads);

    return new Threads{seq};
  case CommandType::Variables: {
    IfInvalidArgsReturn(Variables);

    int var_ref = args["variablesReference"];
    std::optional<u32> start{};
    std::optional<u32> count{};
    if (args.contains("start")) {
      start = args.at("start");
    }
    if (args.contains("count")) {
      count = args.at("count");
    }
    return new Variables{seq, var_ref, start, count};
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