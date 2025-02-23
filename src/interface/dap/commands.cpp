/** LICENSE TEMPLATE */
#include "commands.h"
#include "custom_commands.h"
#include "invalid.h"

#include "bp.h"
#include "common.h"
#include "event_queue.h"
#include "events/event.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "parse_buffer.h"
#include "symbolication/callstack.h"
#include "utils/logger.h"
#include "utils/util.h"
#include <algorithm>
#include <fmt/core.h>
#include <fmt/format.h>
#include <iterator>
#include <optional>
#include <string>
#include <supervisor.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <task_scheduling.h>
#include <tracer.h>
#include <utils/base64.h>

namespace fmt {
namespace ui = mdb::ui;
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

      auto sz = 1u;
      auto max = msg.variables.size();
      auto it = fmt::format_to(ctx.out(), R"({{ "id": {}, "format": "{}","variables":{{)", msg.id.value_or(-1),
                               msg.format);
      for (const auto &[k, v] : msg.variables) {
        if (sz < max) {
          it = fmt::format_to(it, R"("{}":"{}", )", k, v);
        } else {
          it = fmt::format_to(it, R"("{}":"{}")", k, v);
        }
        ++sz;
      }

      return fmt::format_to(it, R"(}}, "showUser":{}}})", msg.show_user);
    }
  }
};

} // namespace fmt

#define GetOrSendError(name)                                                                                      \
  auto name = GetSupervisor();                                                                                    \
  if (!name || name->IsExited()) {                                                                                \
    return new ErrorResponse{StackTrace::Request, this, fmt::format("Process no longer live: {}", mPid), {}};     \
  }

namespace mdb {
ui::UIResultPtr
ui::UICommand::LogExecute() noexcept
{
  auto start = std::chrono::high_resolution_clock::now();
  auto result = Execute();
  const auto commandExecTime = MicroSecondsSince(start);
  DBGLOG(perf, "[command]: {} executed in {} us", name(), commandExecTime);
  return result;
}

namespace ui {
TraceeController *
UICommand::GetSupervisor() noexcept
{
  return mDAPClient->GetSupervisor(mPid);
}
} // namespace ui

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
    : ui::UIResult(false, cmd), mPid(cmd->mPid), command(command), short_message(std::move(short_message)),
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","message":"{}","body":{{"error":{}}}}})",
      seq, request_seq, mPid, command, *short_message, m);
  } else if (short_message && !message) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","message":"{}"}})",
      seq, request_seq, mPid, command, *short_message);
  } else if (!short_message && message) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","body":{{"error":{}}}}})",
      seq, request_seq, mPid, command, *message);
  } else {
    fmt::format_to(
      outIt, R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}"}})",
      seq, request_seq, mPid, command);
  }
  return result;
}

std::pmr::string
PauseResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt, R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"pause"}})",
      seq, request_seq, mPid);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"pause","message":"taskwasnotrunning"}})",
      seq, request_seq, mPid);
  }
  return result;
}

UIResultPtr
Pause::Execute() noexcept
{
  GetOrSendError(target);

  ASSERT(target, "No target {}", mPid);
  auto task = target->GetTaskByTid(pauseArgs.threadId);
  if (task->IsStopped()) {
    return new PauseResponse{false, this};
  }
  const bool success = target->SetAndCallRunAction(
    task->mTid, std::make_shared<ptracestop::StopImmediately>(*target, *task, StoppedReason::Pause));
  return new PauseResponse{success, this};
}

std::pmr::string
ReverseContinueResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"reverseContinue","body":{{"allThreadsContinued":true}}}})",
      seq, request_seq, mPid, continue_all);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"reverseContinue","message":"notStopped"}})",
      seq, request_seq, mPid);
  }
  return result;
}

ReverseContinue::ReverseContinue(UICommandArg arg, int thread_id) noexcept : UICommand(arg), thread_id(thread_id)
{
}

UIResultPtr
ReverseContinue::Execute() noexcept
{
  auto res = new ReverseContinueResponse{true, this};
  auto target = GetSupervisor();
  // TODO: This is the only command where it's ok to get a nullptr for target, in that case, we should just pick
  // _any_ target, and use that to resume backwards (since RR is the controller.).
  ASSERT(target, "must have target.");
  auto ok = target->ReverseResumeTarget(tc::ResumeAction{
    .type = tc::RunType::Continue, .target = tc::ResumeTarget::AllNonRunningInProcess, .mDeliverSignal = 0});
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"continue","body":{{"allThreadsContinued":{}}}}})",
      seq, request_seq, mPid, continue_all);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"continue","message":"notStopped"}})",
      seq, request_seq, mPid);
  }
  return result;
}

UIResultPtr
Continue::Execute() noexcept
{
  GetOrSendError(target);
  auto res = new ContinueResponse{true, this};
  res->continue_all = continue_all;
  if (continue_all && !target->SomeTaskCanBeResumed()) {
    std::vector<Tid> running_tasks{};
    for (const auto &entry : target->GetThreads()) {
      if (!entry.mTask->IsStopped() || entry.mTask->mTracerVisibleStop) {
        running_tasks.push_back(entry.mTid);
      }
    }
    DBGLOG(core, "Denying continue request, target is running ([{}])", fmt::join(running_tasks, ", "));
    res->success = false;
  } else {
    res->success = true;
    if (continue_all) {
      DBGLOG(core, "continue all");
      const int deliverNonSigtrapSignal = -1;
      target->ResumeTarget(tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess,
                                            deliverNonSigtrapSignal});
    } else {
      DBGLOG(core, "continue single thread: {}", thread_id);
      auto t = target->GetTaskByTid(thread_id);
      target->ResumeTask(*t, {tc::RunType::Continue, tc::ResumeTarget::Task, -1});
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
    fmt::format_to(
      outIt, R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"next"}})",
      seq, request_seq, mPid);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"next","message":"notStopped"}})",
      seq, request_seq, mPid);
  }
  return result;
}

UIResultPtr
Next::Execute() noexcept
{
  GetOrSendError(target);

  auto task = target->GetTaskByTid(thread_id);

  if (!task->IsStopped()) {
    return new NextResponse{false, this};
  }

  bool success = false;
  switch (granularity) {
  case SteppingGranularity::Instruction:
    success =
      target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::InstructionStep>(*target, *task, 1));
    break;
  case SteppingGranularity::Line:
    success = target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::LineStep>(*target, *task, 1));
    break;
  case SteppingGranularity::LogicalBreakpointLocation:
    TODO("Next::execute granularity=SteppingGranularity::LogicalBreakpointLocation")
    break;
  }
  return new NextResponse{success, this};
}

std::pmr::string
StepBackResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stepBack"}})", seq,
      request_seq, mPid);
  } else {
    std::string_view error;
    switch (mResult) {
    case Result::Success:
      PANIC("Invariant broken");
    case Result::NotStopped:
      error = "notStopped";
      break;
    case Result::NotReplaySession:
      error = "notReplaySession";
      break;
    }
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"stepBack","message":"{}"}})",
      seq, request_seq, mPid, error);
  }
  return result;
}

UIResultPtr
StepBack::Execute() noexcept
{
  auto target = GetSupervisor();
  ASSERT(target, "must have target");

  if (!target->IsReplaySession()) {
    return new StepBackResponse{StepBackResponse::Result::NotReplaySession, this};
  } else if (target->IsRunning()) {
    // During reverse execution, because we are RR-oriented, the entire process will be stopped, so we don't have
    // to actually check individual tasks here.
    return new StepBackResponse{StepBackResponse::Result::NotStopped, this};
  }

  target->ReverseResumeTarget(tc::ResumeAction{
    .type = tc::RunType::Step, .target = tc::ResumeTarget::AllNonRunningInProcess, .mDeliverSignal = 0});
  return new StepBackResponse{StepBackResponse::Result::Success, this};
}

std::pmr::string
StepInResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt, R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stepIn"}})",
      seq, request_seq, mPid);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"stepIn","message":"notStopped"}})",
      seq, request_seq, mPid);
  }
  return result;
}

UIResultPtr
StepIn::Execute() noexcept
{
  GetOrSendError(target);

  auto task = target->GetTaskByTid(thread_id);

  if (!task->IsStopped()) {
    return new StepInResponse{false, this};
  }

  auto proceeder = ptracestop::StepInto::create(*target, *task);

  if (!proceeder) {
    return new ErrorResponse{
      Request, this,
      std::make_optional("No line table information could be found - abstract stepping not possible."),
      std::nullopt};
  }

  const bool success = target->SetAndCallRunAction(task->mTid, std::move(proceeder));
  return new StepInResponse{success, this};
}

std::pmr::string
StepOutResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  if (success) {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stepOut"}})", seq,
      request_seq, mPid);
  } else {
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"stepOut","message":"notStopped"}})",
      seq, request_seq, mPid);
  }
  return result;
}

UIResultPtr
StepOut::Execute() noexcept
{
  GetOrSendError(target);
  auto task = target->GetTaskByTid(thread_id);

  if (!task->IsStopped()) {
    return new StepOutResponse{false, this};
  }
  const auto req = CallStackRequest::partial(2);
  auto resume_addrs = task->UnwindReturnAddresses(target, req);
  ASSERT(resume_addrs.size() >= static_cast<std::size_t>(req.count), "Could not find frame info");
  const auto rip = resume_addrs[1];
  auto loc = target->GetOrCreateBreakpointLocation(rip);
  if (!loc.is_expected()) {
    return new StepOutResponse{false, this};
  }
  auto user = target->GetUserBreakpoints().create_loc_user<FinishBreakpoint>(*target, std::move(loc), task->mTid,
                                                                             task->mTid);
  bool success = target->SetAndCallRunAction(
    task->mTid, std::make_shared<ptracestop::FinishFunction>(*target, *task, user, false));
  return new StepOutResponse{success, this};
}

SetBreakpointsResponse::SetBreakpointsResponse(bool success, ui::UICommandPtr cmd,
                                               BreakpointRequestKind type) noexcept
    : ui::UIResult(success, cmd), mType(type)
{
}

std::pmr::string
SetBreakpointsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(mdb::SystemPagesInBytes(1) / 2);
  auto outIt = std::back_inserter(result);
  std::pmr::vector<std::pmr::string> serialized_bkpts{arenaAllocator};
  serialized_bkpts.reserve(mBreakpoints.size());
  for (auto &bp : mBreakpoints) {
    serialized_bkpts.push_back(bp.serialize(arenaAllocator));
  }
  switch (this->mType) {
  case BreakpointRequestKind::source:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"setBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, mPid, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::function:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"setFunctionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, mPid, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::instruction:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"setInstructionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, mPid, fmt::join(serialized_bkpts, ","));
    break;
  case BreakpointRequestKind::exception:
    fmt::format_to(
      outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":{},"command":"setExceptionBreakpoints","body":{{"breakpoints":[{}]}}}})",
      seq, request_seq, mPid, success, fmt::join(serialized_bkpts, ","));
    break;
  default:
    PANIC("DAP doesn't expect Tracer breakpoints");
  }
  return result;
}

void
SetBreakpointsResponse::AddBreakpoint(Breakpoint &&bp) noexcept
{
  mBreakpoints.push_back(std::move(bp));
}

SetBreakpoints::SetBreakpoints(UICommandArg arg, nlohmann::json &&arguments) noexcept
    : ui::UICommand(arg), args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetBreakpoints::Execute() noexcept
{
  GetOrSendError(target);
  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::source};

  ASSERT(args.contains("source"), "setBreakpoints request requires a 'source' field");
  ASSERT(args.at("source").contains("path"), "source field requires a 'path' field");
  const std::string file = args["source"]["path"];
  Set<BreakpointSpecification> srcBpSpecs;
  for (const auto &src_bp : args.at("breakpoints")) {
    ASSERT(src_bp.contains("line"), "Source breakpoint requires a 'line' field");
    const u32 line = src_bp["line"];
    auto column = get<u32>(src_bp, "column");
    auto hitCondition = get<std::string>(src_bp, "hitCondition");
    auto logMessage = get<std::string>(src_bp, "logMessage");
    auto condition = get<std::string>(src_bp, "condition");

    srcBpSpecs.insert(BreakpointSpecification::Create<SourceBreakpointSpecPair>(
      std::move(condition), std::move(hitCondition), file,
      SourceBreakpointSpec{.line = line, .column = column, .log_message = std::move(logMessage)}));
  }

  target->SetSourceBreakpoints(file, srcBpSpecs);

  using BP = ui::dap::Breakpoint;

  for (const auto &[bp, ids] : target->GetUserBreakpoints().bps_for_source(file)) {
    for (const auto id : ids) {
      const auto user = target->GetUserBreakpoints().GetUserBreakpoint(id);
      res->AddBreakpoint(BP::from_user_bp(*user));
    }
  }

  return res;
}

SetExceptionBreakpoints::SetExceptionBreakpoints(UICommandArg arg, nlohmann::json &&args) noexcept
    : ui::UICommand{arg}, args(std::move(args))
{
}

UIResultPtr
SetExceptionBreakpoints::Execute() noexcept
{
  DBGLOG(core, "exception breakpoints not yet implemented");
  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::exception};
  return res;
}

SetInstructionBreakpoints::SetInstructionBreakpoints(UICommandArg arg, nlohmann::json &&arguments) noexcept
    : UICommand{arg}, args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetInstructionBreakpoints::Execute() noexcept
{
  GetOrSendError(target);

  using BP = ui::dap::Breakpoint;
  Set<BreakpointSpecification> bps{};
  const auto ibps = args.at("breakpoints");
  for (const auto &ibkpt : ibps) {
    ASSERT(ibkpt.contains("instructionReference") && ibkpt["instructionReference"].is_string(),
           "instructionReference field not in args or wasn't of type string");
    std::string_view addr_str;
    ibkpt["instructionReference"].get_to(addr_str);
    bps.insert(BreakpointSpecification::Create<InstructionBreakpointSpec>({}, {}, std::string{addr_str}));
  }

  target->SetInstructionBreakpoints(bps);

  auto res = new SetBreakpointsResponse{true, this, BreakpointRequestKind::instruction};
  auto &userBreakpoints = target->GetUserBreakpoints();
  res->mBreakpoints.reserve(userBreakpoints.instruction_breakpoints.size());

  for (const auto &[k, id] : userBreakpoints.instruction_breakpoints) {
    res->AddBreakpoint(BP::from_user_bp(*userBreakpoints.GetUserBreakpoint(id)));
  }

  res->success = true;

  return res;
}

SetFunctionBreakpoints::SetFunctionBreakpoints(UICommandArg arg, nlohmann::json &&arguments) noexcept
    : UICommand{arg}, args(std::move(arguments))
{
  ASSERT(args.contains("breakpoints") && args.at("breakpoints").is_array(),
         "Arguments did not contain 'breakpoints' field or wasn't an array");
}

UIResultPtr
SetFunctionBreakpoints::Execute() noexcept
{
  GetOrSendError(target);

  using BP = ui::dap::Breakpoint;
  Set<BreakpointSpecification> bkpts{};
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

    bkpts.insert(BreakpointSpecification::Create<FunctionBreakpointSpec>({}, {}, fn_name, is_regex));
  }

  target->SetFunctionBreakpoints(bkpts);
  for (const auto &user : target->GetUserBreakpoints().AllUserBreakpoints()) {
    if (user->mKind == LocationUserKind::Function) {
      res->AddBreakpoint(BP::from_user_bp(*user));
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
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":{},"command":"writeMemory","body":{{"bytesWritten":{}}}}})",
    seq, request_seq, mPid, success, bytes_written);
  return result;
}

WriteMemory::WriteMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset,
                         std::vector<u8> &&bytes) noexcept
    : ui::UICommand(arg), address(address), offset(offset), bytes(std::move(bytes))
{
}

UIResultPtr
WriteMemory::Execute() noexcept
{
  GetOrSendError(target);

  auto response = new WriteMemoryResponse{false, this};
  response->bytes_written = 0;
  if (address) {
    const auto result = target->GetInterface().WriteBytes(address.value(), bytes.data(), bytes.size());
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"readMemory","body":{{"address":"{}","unreadableBytes":{},"data":"{}"}}}})",
      seq, request_seq, mPid, first_readable_address, unreadable_bytes, data_base64);
  } else {
    TODO("non-success for ReadMemory");
  }
  return result;
}

ReadMemory::ReadMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept
    : UICommand{arg}, address(address), offset(offset), bytes(bytes)
{
}

UIResultPtr
ReadMemory::Execute() noexcept
{
  if (address) {
    GetOrSendError(target);
    auto sv = target->ReadToVector(*address, bytes);
    auto res = new ReadMemoryResponse{true, this};
    res->data_base64 = mdb::encode_base64(sv->span());
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
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"configurationDone"}})",
    seq, request_seq, mPid);
  return result;
}

UIResultPtr
ConfigurationDone::Execute() noexcept
{
  auto supervisor = GetSupervisor();
  ASSERT(supervisor, "Requires a supervisor");
  // Debug Adapter supporting client should see the following order:
  // ConfigDone response
  // Launch/attach response
  // <continued events from resuming>
  // It's a bit contrived. But this part of the protocol just is.
  mDAPClient->PushDelayedEvent(new ConfigurationDoneResponse{true, this});
  mDAPClient->ConfigDone(mPid);
  supervisor->ConfigurationDone();
  using namespace tc;
  switch (supervisor->GetSessionType()) {
  case TargetSession::Launched: {
    DBGLOG(core, "configurationDone - resuming target {}", supervisor->TaskLeaderTid());
    supervisor->ResumeTarget(ResumeAction{RunType::Continue, ResumeTarget::AllNonRunningInProcess, 0});
    break;
  }
  case TargetSession::Attached:
    if (supervisor->IsReplaySession()) {
      supervisor->ResumeTarget(ResumeAction{RunType::Continue, ResumeTarget::AllNonRunningInProcess, 0});
    } else {
      DBGLOG(core, "configurationDone - doing nothing for normal attach sessions {}", supervisor->TaskLeaderTid());
    }
    break;
  }

  return nullptr;
}

std::pmr::string
DisconnectResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"disconnect"}})", seq,
    request_seq, mPid);
  return result;
}

Disconnect::Disconnect(UICommandArg arg, bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept
    : UICommand{arg}, restart(restart), mTerminateTracee(terminate_debuggee), mSuspendTracee(suspend_debuggee)
{
}

UIResultPtr
Disconnect::Execute() noexcept
{
  // We don't allow for child sessions to be terminated, and not have the entire application torn down.
  // We only allow for suspension, or detaching individual child sessions. This behavior is also mimicked for RR
  // sessions, as destroying a process would invalidate the entire application trace.
  GetOrSendError(target);

  if (mTerminateTracee) {
    Tracer::Get().TerminateSession();
  } else {
    target->Disconnect();
  }
  mDAPClient->PushDelayedEvent(new DisconnectResponse{true, this});
  mDAPClient->PushDelayedEvent(new TerminatedEvent{mPid});
  return nullptr;
}

Initialize::Initialize(UICommandArg arg, nlohmann::json &&arguments) noexcept
    : UICommand{arg}, args(std::move(arguments))
{
}

UIResultPtr
Initialize::Execute() noexcept
{
  DBGLOG(core, "Executing initialize request.");
  bool RRSession = false;
  if (args.contains("RRSession")) {
    RRSession = args.at("RRSession");
  }
  std::string sessionId = args.at("sessionId");
  return new InitializeResponse{sessionId, RRSession, true, this};
}

InitializeResponse::InitializeResponse(std::string sessionId, bool rrsession, bool ok, UICommandPtr cmd) noexcept
    : UIResult(ok, cmd), mSessionId(std::move(sessionId)), RRSession(rrsession)
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
  cfg_body["supportsConditionalBreakpoints"] = true;
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
  cfg_body["supportsLogPoints"] = true;
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

  std::pmr::string res{arenaAllocator};

  fmt::format_to(
    std::back_inserter(res),
    R"({{"seq":0,"request_seq":{},"processId":"{}","type":"response","success":true,"command":"initialize","body":{}}})",
    request_seq, mSessionId, cfg_body.dump());
  return res;
}

std::pmr::string
LaunchResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"launch", "body": {{ "processId": {}}}}})",
    seq, request_seq, mPid,
    mProcessId.and_then([](pid_t value) -> std::optional<std::string> { return fmt::format("{}", value); })
      .value_or("null"));
  return result;
}

Launch::Launch(UICommandArg arg, SessionId &&id, bool stopOnEntry, Path &&program,
               std::vector<std::string> &&program_args,
               std::optional<BreakpointBehavior> breakpointBehavior) noexcept
    : UICommand{arg}, mStopOnEntry{stopOnEntry}, mProgram{std::move(program)},
      mProgramArgs{std::move(program_args)}, mBreakpointBehavior{breakpointBehavior},
      mRequestingSessionId{std::move(id)}
{
}

UIResultPtr
Launch::Execute() noexcept
{
  const auto processId = Tracer::Launch(mDAPClient, mRequestingSessionId, mStopOnEntry, mProgram,
                                        std::move(mProgramArgs), mBreakpointBehavior);
  mDAPClient->PrepareLaunch(mRequestingSessionId, processId,
                            new LaunchResponse{std::move(mRequestingSessionId), processId, true, this});
  return nullptr;
}

LaunchResponse::~LaunchResponse() noexcept {}

std::pmr::string
AttachResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt, R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"attach"}})",
    seq, request_seq, mPid);
  return result;
}

Attach::Attach(UICommandArg arg, SessionId &&sessionId, AttachArgs &&args) noexcept
    : UICommand{arg}, mRequestingSessionId{std::move(sessionId)}, attachArgs{std::move(args)}
{
}

UIResultPtr
Attach::Execute() noexcept
{
  const auto processId = Tracer::Get().Attach(mDAPClient, mRequestingSessionId, attachArgs);
  mDAPClient->PrepareAttach(mRequestingSessionId, processId, new AttachResponse{processId, true, this});

  return nullptr;
}

std::pmr::string
TerminateResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256);
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"terminate"}})", seq,
    request_seq, mPid);
  return result;
}

UIResultPtr
Terminate::Execute() noexcept
{
  Tracer::Get().TerminateSession();
  return new TerminateResponse{true, this};
}

std::pmr::string
ThreadsResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (threads.size() * 64));
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"threads","body":{{"threads":[{}]}}}})",
    seq, request_seq, mPid, fmt::join(threads, ","));
  return result;
}

UIResultPtr
Threads::Execute() noexcept
{
  GetOrSendError(target);

  auto response = new ThreadsResponse{true, this};
  response->threads.reserve(target->GetThreads().size());
  auto &it = target->GetInterface();

  if (it.mFormat == TargetFormat::Remote) {
    auto res =
      it.RemoteConnection()->QueryTargetThreads({target->TaskLeaderTid(), target->TaskLeaderTid()}, false);
    ASSERT(res.front().pid == target->TaskLeaderTid(), "expected pid == task_leader");
    for (const auto thr : res) {
      if (std::ranges::none_of(target->GetThreads(),
                               [t = thr.tid](const auto &entry) { return entry.mTid == t; })) {
        target->AddTask(TaskInfo::CreateTask(target->GetInterface(), thr.tid, false));
      }
    }
    target->RemoveTasksNotInSet(res);
  }

  for (const auto &entry : target->GetThreads()) {
    const auto tid = entry.mTid;
    response->threads.push_back(Thread{.id = tid, .name = it.GetThreadName(tid)});
  }
  return response;
}

StackTrace::StackTrace(UICommandArg arg, int threadId, std::optional<int> startFrame, std::optional<int> levels,
                       std::optional<StackTraceFormat> format) noexcept
    : UICommand{arg}, threadId(threadId), startFrame(startFrame), levels(levels), format(format)
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
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stackTrace","body":{{"stackFrames":[{}]}}}})",
    seq, request_seq, mPid, fmt::join(stack_frames, ","));
  return result;
}

UIResultPtr
StackTrace::Execute() noexcept
{
  // todo(simon): multiprocessing needs additional work, since DAP does not support it natively.
  GetOrSendError(target);

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
                     .source = Source{.name = src->mFullPath.StringView(), .path = src->mFullPath.StringView()},
                     .line = static_cast<int>(lte->line),
                     .column = static_cast<int>(lte->column),
                     .rip = fmt::format("{}", frame.FramePc())});
      } else if (src) {
        stack_frames.push_back(
          StackFrame{.id = frame.FrameId(),
                     .name = frame.Name().value_or("unknown"),
                     .source = Source{.name = src->mFullPath.StringView(), .path = src->mFullPath.StringView()},
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

Scopes::Scopes(UICommandArg arg, int frameId) noexcept : UICommand{arg}, frameId(frameId) {}

std::pmr::string
ScopesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (256 * scopes.size()));
  auto outIt = std::back_inserter(result);
  fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"scopes","body":{{"scopes":[{}]}}}})",
    seq, request_seq, mPid, fmt::join(scopes, ","));
  return result;
}

ScopesResponse::ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept
    : UIResult(success, cmd), scopes(scopes)
{
}

UIResultPtr
Scopes::Execute() noexcept
{
  auto ctx = Tracer::Get().GetVariableContext(frameId);
  if (!ctx || !ctx->IsValidContext() || ctx->mType != ContextType::Frame) {
    return new ErrorResponse{Request, this, fmt::format("Invalid variable context for {}", frameId), {}};
  }
  auto frame = ctx->GetFrame(frameId);
  if (!frame) {
    return new ScopesResponse{false, this, {}};
  }
  const auto scopes = frame->Scopes();
  return new ScopesResponse{true, this, scopes};
}

Disassemble::Disassemble(UICommandArg arg, std::optional<AddrPtr> address, int byte_offset, int ins_offset,
                         int ins_count, bool resolve_symbols) noexcept
    : UICommand{arg}, address(address), byte_offset(byte_offset), ins_offset(ins_offset), ins_count(ins_count),
      resolve_symbols(resolve_symbols)
{
}

UIResultPtr
Disassemble::Execute() noexcept
{
  if (address) {
    GetOrSendError(target);
    auto res = new DisassembleResponse{true, this};
    res->instructions.reserve(ins_count);
    int remaining = ins_count;
    if (ins_offset < 0) {
      const int negative_offset = std::abs(ins_offset);
      sym::zydis_disasm_backwards(target, address.value(), static_cast<u32>(negative_offset), res->instructions);
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
      sym::zydis_disasm(target, address.value(), static_cast<u32>(std::abs(ins_offset)), remaining,
                        res->instructions);
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
  auto it = fmt::format_to(
    outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"disassemble","body":{{"instructions":[)",
    seq, request_seq, mPid);
  auto count = 0;
  for (const auto &inst : instructions) {
    if (count > 0) {
      *it++ = ',';
    }
    it = fmt::format_to(it, R"({})", inst);
    count++;
  }
  it = fmt::format_to(it, R"(]}}}})");
  return result;
}

Evaluate::Evaluate(UICommandArg arg, std::string &&expression, std::optional<int> frameId,
                   std::optional<EvaluationContext> context) noexcept
    : UICommand{arg}, expr(std::move(expression)), frameId(frameId),
      context(context.value_or(EvaluationContext::Watch))
{
}

UIResultPtr
Evaluate::Execute() noexcept
{
  switch (context) {
  case EvaluationContext::Watch:
    [[fallthrough]];
  case EvaluationContext::Repl: {
    Allocator alloc{mDAPClient->GetResponseArenaAllocator()};
    auto result = Tracer::Get().EvaluateDebugConsoleExpression(expr, true, &alloc);
    return new EvaluateResponse{true, this, {}, result, {}, {}};
  }
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
Evaluate::PrepareEvaluateCommand(UICommandArg arg, const nlohmann::json &args)
{
  IfInvalidArgsReturn(Evaluate);

  std::string expr = args.at("expression");
  std::optional<int> frameId{};
  EvaluationContext ctx{};
  if (args.contains("frameId")) {
    frameId = args.at("frameId");
  }

  std::string_view context;
  args.at("context").get_to(context);
  ctx = Evaluate::parse_context(context);

  return new ui::dap::Evaluate{arg, std::move(expr), frameId, ctx};
}

EvaluateResponse::EvaluateResponse(bool success, Evaluate *cmd, std::optional<int> variablesReference,
                                   std::pmr::string *evalResult, std::optional<std::string> &&type,
                                   std::optional<std::string> &&memoryReference) noexcept
    : UIResult(success, cmd), result(evalResult), type(std::move(type)),
      variablesReference(variablesReference.value_or(0)), memoryReference(std::move(memoryReference))
{
}

std::pmr::string
EvaluateResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string evalResponseResult{arenaAllocator};
  evalResponseResult.reserve(1024);
  if (success) {
    fmt::format_to(
      std::back_inserter(evalResponseResult),
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"evaluate","body":{{ "result":"{}", "variablesReference":{} }}}})",
      seq, request_seq, mPid, DebugAdapterProtocolString{*result}, variablesReference);
  } else {
    fmt::format_to(
      std::back_inserter(evalResponseResult),
      R"({{"seq":0,"request_seq":{},"type":"response","success":false,"command":"evaluate","body":{{ "error":{{ "id": -1, "format": "{}" }} }}}})",
      request_seq, success, DebugAdapterProtocolString{*result});
  }
  return evalResponseResult;
}

Variables::Variables(UICommandArg arg, VariableReferenceId var_ref, std::optional<u32> start,
                     std::optional<u32> count) noexcept
    : UICommand{arg}, mVariablesReferenceId(var_ref), start(start), count(count)
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
  auto requestedContext = Tracer::Get().GetVariableContext(mVariablesReferenceId);
  if (!requestedContext || !requestedContext->IsValidContext()) {
    return error(fmt::format("Could not find variable with variablesReference {}", mVariablesReferenceId));
  }
  auto &context = *requestedContext;
  auto frame = context.GetFrame(mVariablesReferenceId);
  if (!frame) {
    return error(
      fmt::format("Could not find frame that's referenced via variablesReference {}", mVariablesReferenceId));
  }

  switch (context.mType) {
  case ContextType::Frame:
    return error(
      fmt::format("Sent a variables request using a reference for a frame is an error.", mVariablesReferenceId));
  case ContextType::Scope: {
    auto scope = frame->Scope(mVariablesReferenceId);
    switch (scope->type) {
    case ScopeType::Arguments: {
      auto vars =
        context.mSymbolFile->GetVariables(*context.mTask->GetSupervisor(), *frame, sym::VariableSet::Arguments);
      return new VariablesResponse{true, this, std::move(vars)};
    }
    case ScopeType::Locals: {
      auto vars =
        context.mSymbolFile->GetVariables(*context.mTask->GetSupervisor(), *frame, sym::VariableSet::Locals);
      return new VariablesResponse{true, this, std::move(vars)};
    }
    case ScopeType::Registers: {
      return new VariablesResponse{true, this, {}};
    } break;
    }
  } break;
  case ContextType::Variable:
    return new VariablesResponse{true, this, context.mSymbolFile->ResolveVariable(context, start, count)};
  case ContextType::Global:
    TODO("Global variables not yet implemented support for");
    break;
  }

  return error(fmt::format("Could not find variable with variablesReference {}", mVariablesReferenceId));
}

VariablesResponse::VariablesResponse(bool success, Variables *cmd, std::vector<Ref<sym::Value>> &&vars) noexcept
    : UIResult(success, cmd), requested_reference(cmd != nullptr ? cmd->mVariablesReferenceId : 0),
      variables(std::move(vars))
{
}

VariablesResponse::~VariablesResponse() noexcept = default;

std::pmr::string
VariablesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(256 + (256 * variables.size()));
  if (variables.empty()) {
    fmt::format_to(
      std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"variables","body":{{"variables":[]}}}})",
      seq, request_seq, mPid);
    return result;
  }
  std::pmr::string variables_contents{arenaAllocator};
  variables_contents.reserve(256 * variables_contents.size());
  auto it = std::back_inserter(variables_contents);
  for (const auto &v : variables) {
    if (auto datvis = v->GetVisualizer(); datvis != nullptr) {

      auto opt = datvis->Serialize(*v, v->mName, v->ReferenceId(), arenaAllocator);
      if (opt) {
        it = fmt::format_to(it, "{},", *opt);
      } else {
        fmt::format_to(
          std::back_inserter(result),
          R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"variables","message":"visualizer failed","body":{{"error":{{"id": -1, "format": "Could not visualize value for '{}'"}} }} }})",
          seq, request_seq, mPid, v->mName);
        return result;
      }
    } else {
      ASSERT(v->GetType()->IsReference(), "Add visualizer & resolver for T* types. It will look more "
                                          "or less identical to CStringResolver & ArrayResolver");
      // Todo: this seem particularly shitty. For many reasons. First we check if there's a visualizer, then we
      // do individual type checking again.
      //  this should be streamlined, to be handled once up front. We also need some way to create "new" types.
      auto span = v->MemoryView();
      const std::uintptr_t ptr = sym::BitCopy<std::uintptr_t>(span);
      auto ptr_str = fmt::format("0x{:x}", ptr);
      const std::string_view name = v->mName.StringView();
      it = fmt::format_to(
        it,
        R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }},)",
        name, ptr_str, *v->GetType(), v->ReferenceId(), v->Address());
    }
  }

  variables_contents.pop_back();

  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"variables","body":{{"variables":[{}]}}}})",
    seq, request_seq, mPid, variables_contents);
  return result;
}

std::optional<std::string_view>
PullStringValue(std::string_view name, const nlohmann::json &value) noexcept
{
  if (value.contains(name) && value[name].is_string()) {
    std::string_view contents;
    value[name].get_to(contents);
    return std::optional<std::string_view>{contents};
  }
  return {};
}

ui::UICommand *
ParseDebugAdapterCommand(const DebugAdapterClient &client, std::string packet) noexcept
{
  using namespace ui::dap;

  auto obj = nlohmann::json::parse(packet, nullptr, false);
  std::string_view cmd_name;
  const std::string req = obj.dump();
  DBGLOG(core, "[dap]: parsed request: {}", req);
  obj["command"].get_to(cmd_name);
  ASSERT(obj.contains("arguments"), "Request did not contain an 'arguments' field: {}", packet);
  ASSERT(obj.contains("processId"),
         "Request '{}' did not contain 'processId' field which is a DAP-extension requirement for MDB. It makes "
         "multiprocess debugging under DAP actually function in a non-catastrophically bad way.",
         cmd_name);
  const u64 seq = obj["seq"];
  const Pid processId = obj["processId"];
  UICommandArg arg{seq, processId};

  const auto cmd = parse_command_type(cmd_name);
  auto &&args = std::move(obj["arguments"]);
  switch (cmd) {
  case CommandType::Attach: {
    IfInvalidArgsReturn(Attach);
    return Attach::create(arg, args);
  }
  case CommandType::BreakpointLocations:
    TODO("Command::BreakpointLocations");
  case CommandType::Completions:
    TODO("Command::Completions");
  case CommandType::ConfigurationDone:
    return new ConfigurationDone{arg};
    break;
  case CommandType::Continue: {
    IfInvalidArgsReturn(Continue);

    bool all_threads = false;
    if (args.contains("singleThread")) {
      const bool b = args["singleThread"];
      all_threads = !b;
    }

    return new Continue{arg, args.at("threadId"), all_threads};
  }
  case CommandType::CustomRequest: {
    if (args.contains("command") && args.contains("arguments")) {
      std::string customCommand;
      args["command"].get_to(customCommand);
      return ParseCustomRequestCommand(client, arg, customCommand, args["arguments"]);
    }
    return new InvalidArgs{arg, "customRequest", {}};
  }
  case CommandType::DataBreakpointInfo:
    TODO("Command::DataBreakpointInfo");
  case CommandType::Disassemble: {
    IfInvalidArgsReturn(Disassemble);

    std::string_view addr_str;
    args["memoryReference"].get_to(addr_str);
    const auto addr = ToAddress(addr_str);
    int offset = args.at("offset");
    int instructionOffset = args.at("instructionOffset");
    int instructionCount = args.at("instructionCount");
    return new ui::dap::Disassemble{arg, addr, offset, instructionOffset, instructionCount, false};
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
    return new Disconnect{arg, restart, terminate_debuggee, suspend_debuggee};
  }
  case CommandType::Evaluate: {
    return Evaluate::PrepareEvaluateCommand(arg, args);
  }
  case CommandType::ExceptionInfo:
    TODO("Command::ExceptionInfo");
  case CommandType::Goto:
    TODO("Command::Goto");
  case CommandType::GotoTargets:
    TODO("Command::GotoTargets");
  case CommandType::Initialize:
    IfInvalidArgsReturn(Initialize);
    return new Initialize{arg, std::move(args)};
  case CommandType::Launch: {
    IfInvalidArgsReturn(Launch);

    SessionId sessionId = args.at("sessionId");
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

    const auto behaviorSetting =
      PullStringValue("breakpointBehavior", args)
        .and_then([](const std::string_view &behavior) -> std::optional<BreakpointBehavior> {
          if (behavior == "Stop all threads") {
            return BreakpointBehavior::StopAllThreadsWhenHit;
          } else if (behavior == "Stop single thread") {
            return BreakpointBehavior::StopOnlyThreadThatHit;
          } else {
            return std::nullopt;
          }
        })
        .value_or(BreakpointBehavior::StopAllThreadsWhenHit);

    return new Launch{
      arg, std::move(sessionId), stopOnEntry, std::move(path), std::move(prog_args), behaviorSetting};
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
    return new Next{arg, thread_id, !single_thread, step_type};
  }
  case CommandType::Pause: {
    IfInvalidArgsReturn(Pause);
    int thread_id = args["threadId"];
    return new Pause(arg, Pause::Args{thread_id});
  }
  case CommandType::ReadMemory: {
    IfInvalidArgsReturn(ReadMemory);

    std::string_view addr_str;
    args.at("memoryReference").get_to(addr_str);
    const auto addr = ToAddress(addr_str);
    const auto offset = args.value("offset", 0);
    const u64 count = args.at("count");
    return new ui::dap::ReadMemory{arg, addr, offset, count};
  }
  case CommandType::Restart:
    TODO("Command::Restart");
  case CommandType::RestartFrame:
    TODO("Command::RestartFrame");
  case CommandType::ReverseContinue: {
    IfInvalidArgsReturn(ReverseContinue);
    int thread_id = args["threadId"];
    return new ui::dap::ReverseContinue{arg, thread_id};
  }
  case CommandType::Scopes: {
    IfInvalidArgsReturn(Scopes);

    const int frame_id = args.at("frameId");
    return new ui::dap::Scopes{arg, frame_id};
  }
  case CommandType::SetBreakpoints:
    IfInvalidArgsReturn(SetBreakpoints);

    return new SetBreakpoints{arg, std::move(args)};
  case CommandType::SetDataBreakpoints:
    TODO("Command::SetDataBreakpoints");
  case CommandType::SetExceptionBreakpoints: {
    IfInvalidArgsReturn(SetExceptionBreakpoints);
    return new SetExceptionBreakpoints{arg, std::move(args)};
  }
  case CommandType::SetExpression:
    TODO("Command::SetExpression");
  case CommandType::SetFunctionBreakpoints:
    IfInvalidArgsReturn(SetFunctionBreakpoints);

    return new SetFunctionBreakpoints{arg, std::move(args)};
  case CommandType::SetInstructionBreakpoints:
    IfInvalidArgsReturn(SetInstructionBreakpoints);

    return new SetInstructionBreakpoints{arg, std::move(args)};
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
    return new ui::dap::StackTrace{arg, args.at("threadId"), startFrame, levels, format_};
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

    return new StepIn{arg, thread_id, single_thread, step_type};
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
    return new ui::dap::StepOut{arg, thread_id, !single_thread};
  }
  case CommandType::Terminate:
    IfInvalidArgsReturn(Terminate);

    return new Terminate{arg};
  case CommandType::TerminateThreads:
    TODO("Command::TerminateThreads");
  case CommandType::Threads:
    IfInvalidArgsReturn(Threads);

    return new Threads{arg};
  case CommandType::Variables: {
    IfInvalidArgsReturn(Variables);

    VariableReferenceId variablesReference = args["variablesReference"];
    std::optional<u32> start{};
    std::optional<u32> count{};
    if (args.contains("start")) {
      start = args.at("start");
    }
    if (args.contains("count")) {
      count = args.at("count");
    }
    return new Variables{arg, variablesReference, start, count};
  }
  case CommandType::WriteMemory: {
    IfInvalidArgsReturn(WriteMemory);
    std::string_view addrString;
    args["memoryReference"].get_to(addrString);
    const auto addr = ToAddress(addrString);
    int offset = 0;
    if (args.contains("offset")) {
      args.at("offset").get_to(offset);
    }

    std::string_view data{};
    args.at("data").get_to(data);

    if (auto bytes = mdb::decode_base64(data); bytes) {
      return new WriteMemory{arg, addr, offset, std::move(bytes.value())};
    } else {
      return new InvalidArgs{arg, "writeMemory", {}};
    }
  }
  case CommandType::ImportScript:
    break;
  case CommandType::UNKNOWN:
    break;
  }
  PANIC("Could not parse command");
  return nullptr;
}

} // namespace ui::dap
} // namespace mdb