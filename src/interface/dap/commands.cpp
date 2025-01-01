#include "commands.h"
#include "bp.h"
#include "common.h"
#include "events/event.h"
#include "fmt/ranges.h"
#include "interface/attach_args.h"
#include "interface/dap/events.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "interface/ui_command.h"
#include "parse_buffer.h"
#include "symbolication/callstack.h"
#include "types.h"
#include "utils/logger.h"
#include "utils/util.h"
#include <algorithm>
#include <fmt/core.h>
#include <fmt/format.h>
#include <interface/dap/interface.h>
#include <iterator>
#include <lib/arena_allocator.h>
#include <memory_resource>
#include <optional>
#include <ptracestop_handlers.h>
#include <string>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <tracer.h>
#include <utils/base64.h>

namespace fmt {

template <> struct formatter<ui::dap::Message>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const ui::dap::Message &msg, FormatContext &ctx) const
  {

    if (msg.variables.empty()) {
      return fmt::format_to(ctx.out(), R"({{"id":{},"format":"{}","showUser":{}}})", msg.id.value_or(-1),
                            msg.format, msg.show_user);
    } else {
      std::vector<char> buf{0};
      buf.reserve(256);
      auto sz = 1u;
      auto max = msg.variables.size();
      for (const auto &[k, v] : msg.variables) {
        if (sz < max) {
          fmt::format_to(std::back_inserter(buf), R"("{}":"{}", )", k, v);
        } else {
          fmt::format_to(std::back_inserter(buf), R"("{}":"{}")", k, v);
        }
        ++sz;
      }
      buf.push_back(0);
      return fmt::format_to(ctx.out(), R"({{ "id": {}, "format": "{}", "variables":{{ {} }}, "showUser":{}}})",
                            msg.id.value_or(-1), msg.format, fmt::join(buf, ""), msg.show_user);
    }
  }
};

} // namespace fmt

ui::UIResultPtr
ui::UICommand::LogExecute() noexcept
{
  auto start = std::chrono::high_resolution_clock::now();
  auto result = Execute();
  const auto duration_us =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
      .count();
  DBGLOG(perf, "[command]: {} executed in {} us", name(), duration_us);
  return result;
}

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

std::pmr::string
ErrorResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (short_message && message) {
    const Message &m = message.value();
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}","body":{{"error":{}}}}})",
      seq, request_seq, command, *short_message, m);
  } else if (short_message && !message) {
    fmt::format_to(
      outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}"}})",
      seq, request_seq, command, *short_message);
  } else if (!short_message && message) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","body":{{"error":{}}}}})",
      seq, request_seq, command, *message);
  } else {
    fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}"}})", seq,
                   request_seq, command);
  }
  return result;
}

std::pmr::string
PauseResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"pause"}})",
                   seq, request_seq);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"pause","message":"taskwasnotrunning"}})",
      seq, request_seq);
  }
  return result;
}

UIResultPtr
Pause::Execute() noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->GetTaskByTid(pauseArgs.threadId);
  if (task->is_stopped()) {
    return new PauseResponse{false, this};
  }
  target->InstallStopActionHandler<ptracestop::StopImmediately>(*task, StoppedReason::Pause);
  return new PauseResponse{true, this};
}

std::pmr::string
ReverseContinueResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"reverseContinue","body":{{"allThreadsContinued":true}}}})",
      seq, request_seq, continue_all);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"reverseContinue","message":"notStopped"}})",
      seq, request_seq);
  }
  return result;
}

ReverseContinue::ReverseContinue(u64 seq, int thread_id) noexcept : UICommand(seq), thread_id(thread_id) {}

UIResultPtr
ReverseContinue::Execute() noexcept
{
  auto res = new ReverseContinueResponse{true, this};
  auto target = dap_client->supervisor();
  auto ok = target->GetInterface().ReverseContinue();
  res->success = ok;
  return res;
}

std::pmr::string
ContinueResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"continue","body":{{"allThreadsContinued":{}}}}})",
      seq, request_seq, continue_all);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"continue","message":"notStopped"}})",
      seq, request_seq);
  }
  return result;
}

UIResultPtr
Continue::Execute() noexcept
{
  auto res = new ContinueResponse{true, this};
  res->continue_all = continue_all;
  auto target = dap_client->supervisor();
  if (continue_all && target->IsRunning()) {
    std::vector<Tid> running_tasks{};
    for (const auto &t : target->GetThreads()) {
      if (!t->is_stopped() || t->tracer_stopped) {
        running_tasks.push_back(t->tid);
      }
    }
    DBGLOG(core, "Denying continue request, target is running ([{}])", fmt::join(running_tasks, ", "));
    res->success = false;
  } else {
    res->success = true;
    if (continue_all) {
      DBGLOG(core, "continue all");
      target->ResumeTask(tc::RunType::Continue);
    } else {
      DBGLOG(core, "continue single thread: {}", thread_id);
      auto t = target->GetTaskByTid(thread_id);
      target->ResumeTask(*t, {tc::RunType::Continue, tc::ResumeTarget::Task});
    }
  }

  return res;
}

std::pmr::string
NextResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"next"}})",
                   seq, request_seq);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"next","message":"notStopped"}})",
      seq, request_seq);
  }
  return result;
}

UIResultPtr
Next::Execute() noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->GetTaskByTid(thread_id);

  if (!task->is_stopped()) {
    return new NextResponse{false, this};
  }

  switch (granularity) {
  case SteppingGranularity::Instruction:
    target->InstallStopActionHandler<ptracestop::InstructionStep>(*task, 1);
    break;
  case SteppingGranularity::Line:
    target->InstallStopActionHandler<ptracestop::LineStep>(*task, 1);
    break;
  case SteppingGranularity::LogicalBreakpointLocation:
    TODO("Next::execute granularity=SteppingGranularity::LogicalBreakpointLocation")
    break;
  }
  return new NextResponse{true, this};
}

std::pmr::string
StepInResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"stepIn"}})",
                   seq, request_seq);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"stepIn","message":"notStopped"}})",
      seq, request_seq);
  }
  return result;
}

UIResultPtr
StepIn::Execute() noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->GetTaskByTid(thread_id);

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

  target->SetAndCallRunAction(task->tid, proceeder);
  return new StepInResponse{true, this};
}

std::pmr::string
StepOutResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"stepOut"}})",
                   seq, request_seq);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"stepOut","message":"notStopped"}})",
      seq, request_seq);
  }
  return result;
}

UIResultPtr
StepOut::Execute() noexcept
{
  auto target = dap_client->supervisor();
  auto task = target->GetTaskByTid(thread_id);

  if (!task->is_stopped()) {
    return new StepOutResponse{false, this};
  }
  const auto req = CallStackRequest::partial(2);
  auto resume_addrs = task->return_addresses(target, req);
  ASSERT(resume_addrs.size() >= static_cast<std::size_t>(req.count), "Could not find frame info");
  const auto rip = resume_addrs[1];
  auto loc = target->GetOrCreateBreakpointLocation(rip);
  if (!loc.is_expected()) {
    return new StepOutResponse{false, this};
  }
  auto user =
    target->GetUserBreakpoints().create_loc_user<FinishBreakpoint>(*target, std::move(loc), task->tid, task->tid);
  target->InstallStopActionHandler<ptracestop::FinishFunction>(*task, user, false);
  return new StepOutResponse{true, this};
}

SetBreakpointsResponse::SetBreakpointsResponse(bool success, ui::UICommandPtr cmd,
                                               BreakpointRequestKind type) noexcept
    : ui::UIResult(success, cmd), type(type), breakpoints()
{
}

std::pmr::string
SetBreakpointsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(utils::SystemPagesInBytes(1) / 2);
  auto outIt = std::back_inserter(result);
  std::pmr::vector<std::pmr::string> serialized_bkpts{arenaAllocator};
  serialized_bkpts.reserve(breakpoints.size());
  for (auto &bp : breakpoints) {
    serialized_bkpts.push_back(bp.serialize(arenaAllocator));
  }
  switch (this->type) {
  case BreakpointRequestKind::source:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"setBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::function:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"setFunctionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::instruction:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"setInstructionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::exception:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"setExceptionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, success, fmt::join(serialized_bkpts, ","));
    break;
  default:
    PANIC("DAP doesn't expect Tracer breakpoints");
  }
  return result;
}

SetBreakpoints::SetBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept
    : ui::UICommand(seq), args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetBreakpoints::Execute() noexcept
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

  target->SetSourceBreakpoints(file, src_bps);

  using BP = ui::dap::Breakpoint;

  for (const auto &[bp, ids] : target->GetUserBreakpoints().bps_for_source(file)) {
    for (const auto id : ids) {
      const auto user = target->GetUserBreakpoints().get_user(id);
      res->breakpoints.push_back(BP::from_user_bp(*user));
    }
  }

  return res;
}

SetExceptionBreakpoints::SetExceptionBreakpoints(std::uint64_t sequence, nlohmann::json &&args) noexcept
    : ui::UICommand{sequence}, args(std::move(args))
{
}

UIResultPtr
SetExceptionBreakpoints::Execute() noexcept
{
  DBGLOG(core, "exception breakpoints not yet implemented");
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
SetInstructionBreakpoints::Execute() noexcept
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
  target->SetInstructionBreakpoints(bps);

  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::instruction};
  res->breakpoints.reserve(target->GetUserBreakpoints().instruction_breakpoints.size());

  for (const auto &[k, id] : target->GetUserBreakpoints().instruction_breakpoints) {
    res->breakpoints.push_back(BP::from_user_bp(*target->GetUserBreakpoints().get_user(id)));
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
SetFunctionBreakpoints::Execute() noexcept
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

  target->SetFunctionBreakpoints(bkpts);
  for (const auto &user : target->GetUserBreakpoints().all_users()) {
    if (user->kind == LocationUserKind::Function) {
      res->breakpoints.push_back(BP::from_user_bp(*user));
    }
  }
  res->success = true;
  return res;
}

std::pmr::string
WriteMemoryResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"writeMemory","body":{{"bytesWritten":{}}}}})",
    seq, request_seq, success, bytes_written);
  return result;
}

WriteMemory::WriteMemory(u64 seq, std::optional<AddrPtr> address, int offset, std::vector<u8> &&bytes) noexcept
    : ui::UICommand(seq), address(address), offset(offset), bytes(std::move(bytes))
{
}

UIResultPtr
WriteMemory::Execute() noexcept
{
  auto supervisor = dap_client->supervisor();
  auto response = new WriteMemoryResponse{false, this};
  response->bytes_written = 0;
  if (address) {
    const auto result = supervisor->GetInterface().WriteBytes(address.value(), bytes.data(), bytes.size());
    response->success = result.success;
    if (result.success) {
      response->bytes_written = result.bytes_written;
    }
  }

  return response;
}

std::pmr::string
ReadMemoryResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + data_base64.size());
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"readMemory","body":{{"address":"{}","unreadableBytes":{},"data":"{}"}}}})",
      seq, request_seq, first_readable_address, unreadable_bytes, data_base64);
  } else {
    TODO("non-success for ReadMemory");
  }
  return result;
}

ReadMemory::ReadMemory(std::uint64_t seq, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept
    : UICommand(seq), address(address), offset(offset), bytes(bytes)
{
}

UIResultPtr
ReadMemory::Execute() noexcept
{
  if (address) {
    auto sv = dap_client->supervisor()->ReadToVector(*address, bytes);
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

std::pmr::string
ConfigurationDoneResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  result.reserve(256);
  fmt::format_to(outIt,
                 R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"configurationDone"}})",
                 seq, request_seq);
  return result;
}

UIResultPtr
ConfigurationDone::Execute() noexcept
{
  Tracer::Instance->config_done(dap_client);
  switch (dap_client->supervisor()->GetSessionType()) {
  case TargetSession::Launched:
    dap_client->supervisor()->ResumeTask(tc::RunType::Continue);
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
Initialize::Execute() noexcept
{
  bool RRSession = false;
  if (args.contains("RRSession")) {
    RRSession = args.at("RRSession");
  }
  return new InitializeResponse{RRSession, true, this};
}

std::pmr::string
DisconnectResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"disconnect"}})",
                 seq, request_seq);
  return result;
}

Disconnect::Disconnect(std::uint64_t seq, bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept
    : UICommand(seq), restart(restart), terminate_tracee(terminate_debuggee), suspend_tracee(suspend_debuggee)
{
}

UIResultPtr
Disconnect::Execute() noexcept
{
  const auto ok = dap_client->supervisor()->GetInterface().DoDisconnect(true);
  if (ok) {
    Tracer::Instance->erase_target(
      [this](auto &ptr) { return ptr->GetDebugAdapterProtocolClient() == dap_client; });
    Tracer::Instance->KeepAlive = !Tracer::Instance->mTracedProcesses.empty();
  }

  return new DisconnectResponse{ok, this};
}

InitializeResponse::InitializeResponse(bool rrsession, bool ok, UICommandPtr cmd) noexcept
    : UIResult(ok, cmd), RRSession(rrsession)
{
}

std::pmr::string
InitializeResponse::Serialize(int, std::pmr::memory_resource *arenaAllocator) const noexcept
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
  cfg_body["supportsStepBack"] = RRSession;
  cfg_body["supportsSingleThreadExecutionRequests"] = !RRSession;
  cfg_body["supportsSetVariable"] = false;
  cfg_body["supportsRestartFrame"] = false;
  cfg_body["supportsGotoTargetsRequest"] = false;
  cfg_body["supportsStepInTargetsRequest"] = false;
  cfg_body["supportsCompletionsRequest"] = false;
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
  cfg_body["supportsWriteMemoryRequest"] = true;
  cfg_body["supportsDisassembleRequest"] = true;
  cfg_body["supportsCancelRequest"] = false;
  cfg_body["supportsBreakpointLocationsRequest"] = false;
  cfg_body["supportsSteppingGranularity"] = true;
  cfg_body["supportsInstructionBreakpoints"] = true;
  cfg_body["supportsExceptionFilterOptions"] = false;

  auto payload = fmt::format(
    R"({{"seq":0,"request_seq":{},"type":"response","success":true,"command":"initialize","body":{}}})",
    request_seq, cfg_body.dump());

  client->write(payload);
  client->write(InitializedEvent{}.Serialize(0, arenaAllocator));
  return std::pmr::string{arenaAllocator};
}

std::pmr::string
LaunchResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"launch"}})",
                 seq, request_seq);
  return result;
}

Launch::Launch(std::uint64_t seq, bool stopOnEntry, Path &&program,
               std::vector<std::string> &&program_args) noexcept
    : UICommand(seq), stopOnEntry(stopOnEntry), program(std::move(program)), program_args(std::move(program_args))
{
}

UIResultPtr
Launch::Execute() noexcept
{
  Tracer::Instance->launch(dap_client, stopOnEntry, std::move(program), std::move(program_args));
  return new LaunchResponse{true, this};
}

std::pmr::string
AttachResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"attach"}})",
                 seq, request_seq);
  return result;
}

Attach::Attach(std::uint64_t seq, AttachArgs &&args) noexcept : UICommand(seq), attachArgs(std::move(args)) {}

UIResultPtr
Attach::Execute() noexcept
{
  const auto res = Tracer::Instance->attach(attachArgs);
  return new AttachResponse{res, this};
}

std::pmr::string
TerminateResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(outIt, R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"terminate"}})",
                 seq, request_seq);
  return result;
}

UIResultPtr
Terminate::Execute() noexcept
{
  const auto ok = dap_client->supervisor()->GetInterface().DoDisconnect(true);
  if (ok) {
    dap_client->post_event(new TerminatedEvent{});
    Tracer::Instance->erase_target(
      [this](auto &ptr) { return ptr->GetDebugAdapterProtocolClient() == dap_client; });
    Tracer::Instance->KeepAlive = !Tracer::Instance->mTracedProcesses.empty();
  }
  return new TerminateResponse{ok, this};
}

std::pmr::string
ThreadsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (threads.size() * 64));
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"threads","body":{{"threads":[{}]}}}})",
    seq, request_seq, fmt::join(threads, ","));
  return result;
}

UIResultPtr
Threads::Execute() noexcept
{
  // todo(simon): right now, we only support 1 process, but theoretically the current design
  // allows for more; it would require some work to get the DAP protocol to play nicely though.
  // therefore we just hand back the threads of the currently active target
  auto response = new ThreadsResponse{true, this};

  auto target = dap_client->supervisor();

  response->threads.reserve(target->GetThreads().size());
  auto &it = target->GetInterface();

  if (it.format == TargetFormat::Remote) {
    auto res = it.RemoteConnection()->query_target_threads({target->TaskLeaderTid(), target->TaskLeaderTid()});
    ASSERT(res.front().pid == target->TaskLeaderTid(), "expected pid == task_leader");
    for (const auto thr : res) {
      if (std::ranges::none_of(target->GetThreads(), [t = thr.tid](const auto &a) { return a->tid == t; })) {
        target->AddTask(TaskInfo::CreateTask(target->GetInterface(), thr.tid, false));
      }
    }

    target->RemoveTaskIf([&](const auto &thread) {
      return std::none_of(res.begin(), res.end(), [&](const auto pidtid) { return pidtid.tid == thread->tid; });
    });
  }

  for (const auto &thread : target->GetThreads()) {
    const auto tid = thread->tid;
    response->threads.push_back(Thread{.id = tid, .name = it.GetThreadName(tid)});
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

std::pmr::string
StackTraceResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  // Estimated size per stack frame; 105 for the formatting string, 18 for the address, 2+2 for line:col, 256 for
  // name and path
  // + format string for response with some additional spill.
  result.reserve(256 + ((105 + 18 + 2 + 2 + 256) * stack_frames.size()));
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"stackTrace","body":{{"stackFrames":[{}]}}}})",
    seq, request_seq, fmt::join(stack_frames, ","));
  return result;
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
StackTrace::Execute() noexcept
{
  // todo(simon): multiprocessing needs additional work, since DAP does not support it natively.
  auto target = dap_client->supervisor();
  if(!target || target->IsExited()) {
    return new ErrorResponse{StackTrace::Request, this, fmt::format("Process has already died: {}", threadId), {}};
  }
  auto task = target->GetTaskByTid(threadId);
  if (task == nullptr) {
    return new ErrorResponse{StackTrace::Request, this, fmt::format("Thread with ID {} not found", threadId), {}};
  }
  auto &cfs = target->BuildCallFrameStack(*task, CallStackRequest::full());
  std::vector<StackFrame> stack_frames{};
  stack_frames.reserve(cfs.FramesCount());
  for (auto &frame : cfs.GetFrames()) {
    if (frame.GetFrameType() == sym::FrameType::Full) {
      const auto [src, lte] = frame.GetLineTableEntry();
      if (src && lte) {
        stack_frames.push_back(
          StackFrame{.id = frame.FrameId(),
                     .name = frame.Name().value_or("unknown"),
                     .source = Source{.name = src->full_path->c_str(), .path = src->full_path->c_str()},
                     .line = static_cast<int>(lte->line),
                     .column = static_cast<int>(lte->column),
                     .rip = fmt::format("{}", frame.FramePc())});
      } else if(src) {
        stack_frames.push_back(
          StackFrame{.id = frame.FrameId(),
                     .name = frame.Name().value_or("unknown"),
                     .source = Source{.name = src->full_path->c_str(), .path = src->full_path->c_str()},
                     .line = 0,
                     .column = 0,
                     .rip = fmt::format("{}", frame.FramePc())});
      } else {
      stack_frames.push_back(StackFrame{.id = frame.FrameId(),
                                        .name = frame.Name().value_or("unknown"),
                                        .source = std::nullopt,
                                        .line = 0,
                                        .column = 0,
                                        .rip = fmt::format("{}", frame.FramePc())});
      }

    } else {
      stack_frames.push_back(StackFrame{.id = frame.FrameId(),
                                        .name = frame.Name().value_or("unknown"),
                                        .source = std::nullopt,
                                        .line = 0,
                                        .column = 0,
                                        .rip = fmt::format("{}", frame.FramePc())});
    }
  }
  return new StackTraceResponse{true, this, std::move(stack_frames)};
}

Scopes::Scopes(std::uint64_t seq, int frameId) noexcept : UICommand(seq), frameId(frameId) {}

std::pmr::string
ScopesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (256 * scopes.size()));
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"scopes","body":{{"scopes":[{}]}}}})",
    seq, request_seq, fmt::join(scopes, ","));
  return result;
}

ScopesResponse::ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept
    : UIResult(success, cmd), scopes(scopes)
{
}

UIResultPtr
Scopes::Execute() noexcept
{
  auto ctx = Tracer::Instance->var_context(frameId);
  if (!ctx.valid_context() || ctx.type != ContextType::Frame) {
    return new ErrorResponse{Request, this, fmt::format("Invalid variable context for {}", frameId), {}};
  }
  auto frame = ctx.get_frame(frameId);
  if (!frame) {
    return new ScopesResponse{false, this, {}};
  }
  const auto scopes = frame->Scopes();
  return new ScopesResponse{true, this, scopes};
}

Disassemble::Disassemble(std::uint64_t seq, std::optional<AddrPtr> address, int byte_offset, int ins_offset,
                         int ins_count, bool resolve_symbols) noexcept
    : UICommand(seq), address(address), byte_offset(byte_offset), ins_offset(ins_offset), ins_count(ins_count),
      resolve_symbols(resolve_symbols)
{
}

UIResultPtr
Disassemble::Execute() noexcept
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

std::pmr::string
DisassembleResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (256 * instructions.size()));
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"disassemble","body":{{"instructions":[{}]}}}})",
    seq, request_seq, fmt::join(instructions, ","));
  return result;
}

#define IfInvalidArgsReturn(type)                                                                                 \
  if (const auto missing = Validate<type>(seq, args); missing) {                                                  \
    return missing;                                                                                               \
  }

Evaluate::Evaluate(u64 seq, std::string &&expression, std::optional<int> frameId,
                   std::optional<EvaluationContext> context) noexcept
    : UICommand(seq), expr(std::move(expression)), frameId(frameId),
      context(context.value_or(EvaluationContext::Watch))
{
}

UIResultPtr
Evaluate::Execute() noexcept
{
  switch (context) {
  case EvaluationContext::Watch:
    [[fallthrough]];
  case EvaluationContext::Repl:
    [[fallthrough]];
  case EvaluationContext::Hover:
    [[fallthrough]];
  case EvaluationContext::Clipboard:
    [[fallthrough]];
  case EvaluationContext::Variables:
    return new ErrorResponse{Request, this, {}, Message{.format = "could not evaluate"}};
  }
}

EvaluationContext
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

  return EvaluationContext::Repl;
}

/*static*/
UICommand *
Evaluate::PrepareEvaluateCommand(u64 seq, const nlohmann::json &args)
{
  IfInvalidArgsReturn(Evaluate);

  std::string expr = args.at("expression");
  std::optional<int> frameId{};
  EvaluationContext ctx{};
  frameId = args.at("frameId");

  std::string_view context;
  args.at("context").get_to(context);
  ctx = Evaluate::parse_context(context);

  return new ui::dap::Evaluate{seq, std::move(expr), frameId, ctx};
}

EvaluateResponse::EvaluateResponse(bool success, Evaluate *cmd, std::optional<int> variablesReference,
                                   std::string &&result, std::optional<std::string> &&type,
                                   std::optional<std::string> &&memoryReference) noexcept
    : UIResult(success, cmd), result(std::move(result)), type(std::move(type)),
      variablesReference(variablesReference.value_or(0)), memoryReference(std::move(memoryReference))
{
}

std::pmr::string
EvaluateResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(1024);
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"evaluate","body":{{ "result":"{}", "variablesReference":{} }}}})",
      seq, request_seq, success, result, variablesReference);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":0,"request_seq":{},"type":"response","success":false,"command":"evaluate","body":{{ "error":{{ "id": -1, "format": "{}" }} }}}})",
      request_seq, success, result);
  }
  return result;
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
Variables::Execute() noexcept
{
  auto context = Tracer::Instance->var_context(var_ref);
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
    auto scope = frame->Scope(var_ref);
    switch (scope->type) {
    case ScopeType::Arguments: {
      auto vars = context.symbol_file->GetVariables(*context.tc, *frame, sym::VariableSet::Arguments);
      return new VariablesResponse{true, this, std::move(vars)};
    }
    case ScopeType::Locals: {
      auto vars = context.symbol_file->GetVariables(*context.tc, *frame, sym::VariableSet::Locals);
      return new VariablesResponse{true, this, std::move(vars)};
    }
    case ScopeType::Registers: {
      return new VariablesResponse{true, this, {}};
    } break;
    }
  } break;
  case ContextType::Variable:
    return new VariablesResponse{true, this, context.symbol_file->ResolveVariable(context, start, count)};
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

std::pmr::string
VariablesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (256 * variables.size()));
  if (variables.empty()) {
    fmt::format_to(
      std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"variables","body":{{"variables":[]}}}})",
      seq, request_seq);
    return result;
  }
  std::pmr::string variables_contents{arenaAllocator};
  variables_contents.reserve(256 * variables_contents.size());
  auto it = std::back_inserter(variables_contents);
  for (const auto &v : variables) {
    if (auto datvis = v.variable_value->GetVisualizer(); datvis != nullptr) {
      auto opt = datvis->DapFormat(v.variable_value->mName, v.ref, arenaAllocator);
      if (opt) {
        it = fmt::format_to(it, "{},", *opt);
      } else {
        fmt::format_to(
          std::back_inserter(result),
          R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"variables","message":"visualizer failed","body":{{"error":{{"id": -1, "format": "Could not visualize value for '{}'"}} }} }})",
          seq, request_seq, v.variable_value->mName);
        return result;
      }
    } else {
      ASSERT(v.variable_value->GetType()->IsReference(),
             "Add visualizer & resolver for T* types. It will look more "
             "or less identical to CStringResolver & ArrayResolver");
      // Todo: this seem particularly shitty. For many reasons. First we check if there's a visualizer, then we
      // do individual type checking again.
      //  this should be streamlined, to be handled once up front. We also need some way to create "new" types.
      auto span = v.variable_value->MemoryView();
      const std::uintptr_t ptr = sym::bit_copy<std::uintptr_t>(span);
      auto ptr_str = fmt::format("0x{:x}", ptr);
      const std::string_view name = v.variable_value->mName.string_view();
      it = fmt::format_to(
        it,
        R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }},)",
        name, ptr_str, *v.variable_value->GetType(), v.ref, v.variable_value->Address());
    }
  }

  variables_contents.pop_back();

  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"variables","body":{{"variables":[{}]}}}})",
    seq, request_seq, variables_contents);
  return result;
}

InvalidArgs::InvalidArgs(std::uint64_t seq, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
    : UICommand(seq), command(command), missing_arguments(std::move(missing_args))
{
}

UIResultPtr
InvalidArgs::Execute() noexcept
{
  return new InvalidArgsResponse{command, std::move(missing_arguments)};
}

InvalidArgsResponse::InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept
    : command(command), missing_or_invalid(std::move(missing_args))
{
}

std::pmr::string
InvalidArgsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::vector<std::string_view> missing{arenaAllocator};
  std::pmr::vector<const InvalidArg *> parsed_and_invalid{arenaAllocator};
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

  std::pmr::string result{arenaAllocator};
  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":false,"command":"{}","message":"{}"}})", seq,
    request_seq, command, msg);

  return result;
}

ui::UICommand *
ParseDebugAdapterCommand(std::string packet) noexcept
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
    return Evaluate::PrepareEvaluateCommand(seq, args);
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
    Path cwd;
    std::vector<std::string> prog_args;
    if (args.contains("args")) {
      prog_args = args.at("args");
    }

    bool stopOnEntry = false;
    if (args.contains("stopOnEntry")) {
      stopOnEntry = args["stopOnEntry"];
    }

    if (args.contains("env")) {
    }

    if (args.contains("cwd")) {
    }

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
  case CommandType::ReverseContinue: {
    IfInvalidArgsReturn(ReverseContinue);
    int thread_id = args["threadId"];
    return new ui::dap::ReverseContinue{seq, thread_id};
  }
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
  case CommandType::WriteMemory: {
    IfInvalidArgsReturn(WriteMemory);
    std::string_view addr_str;
    args["memoryReference"].get_to(addr_str);
    const auto addr = to_addr(addr_str);
    int offset = 0;
    if (args.contains("offset")) {
      args.at("offset").get_to(offset);
    }

    std::string_view data{};
    args.at("data").get_to(data);

    if (auto bytes = utils::decode_base64(data); bytes) {
      return new WriteMemory{seq, addr, offset, std::move(bytes.value())};
    } else {
      return new InvalidArgs{seq, "writeMemory", {}};
    }
  }
  case CommandType::UNKNOWN:
    break;
  }
  PANIC("Could not parse command");
  return nullptr;
}

} // namespace ui::dap