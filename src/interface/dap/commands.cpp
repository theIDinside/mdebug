/** LICENSE TEMPLATE */

#include "commands.h"

// mdb
#include <bp.h>
#include <common.h>
#include <common/formatter.h>
#include <common/typedefs.h>
#include <event_queue.h>
#include <events/event.h>
#include <interface/dap/custom_commands.h>
#include <interface/dap/dap_defs.h>
#include <interface/dap/events.h>
#include <interface/dap/invalid.h>
#include <interface/dap/parse_buffer.h>
#include <interface/tracee_command/tracee_command_interface.h>
#include <supervisor.h>
#include <symbolication/callstack.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <task_scheduling.h>
#include <tracer.h>
#include <utils/base64.h>
#include <utils/logger.h>
#include <utils/util.h>

// system

// std
#include <algorithm>
#include <iterator>
#include <memory_resource>
#include <optional>
#include <string>

namespace ui = mdb::ui;
template <> struct std::formatter<ui::dap::Message>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const ui::dap::Message &msg, FormatContext &ctx) const
  {

    if (msg.variables.empty()) {
      return std::format_to(
        ctx.out(), R"({{"id":{},"format":"{}","showUser":{}}})", msg.id.value_or(-1), msg.format, msg.show_user);
    } else {

      auto sz = 1u;
      auto max = msg.variables.size();
      auto it = std::format_to(
        ctx.out(), R"({{ "id": {}, "format": "{}","variables":{{)", msg.id.value_or(-1), msg.format);
      for (const auto &[k, v] : msg.variables) {
        if (sz < max) {
          it = std::format_to(it, R"("{}":"{}", )", k, v);
        } else {
          it = std::format_to(it, R"("{}":"{}")", k, v);
        }
        ++sz;
      }

      return std::format_to(it, R"(}}, "showUser":{}}})", msg.show_user);
    }
  }
};

#define GetOrSendError(name)                                                                                      \
  auto name = GetSupervisor();                                                                                    \
  if (!name || name->IsExited()) {                                                                                \
    return new ErrorResponse{ Request, this, std::format("Session '{}' could not be found.", mSessionId), {} };   \
  }

namespace mdb {

namespace ui {
TraceeController *
UICommand::GetSupervisor() noexcept
{
  return mDAPClient->GetSupervisor(mSessionId);
}
} // namespace ui

namespace ui::dap {

template <typename Res>
inline std::optional<Res>
get(const mdbjson::JsonValue &obj, std::string_view field)
{
  if (obj.Contains(field)) {
    Res result = obj[field];
    return std::move(result);
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

struct ErrorResponse final : ui::UIResult
{
  ErrorResponse(std::string_view command,
    ui::UICommandPtr cmd,
    std::optional<std::string> &&shortMessage,
    std::optional<Message> &&message) noexcept
      : ui::UIResult(false, cmd), mPid(cmd->mSessionId), mCommand(command), mShortMessage(std::move(shortMessage)),
        mMessage(std::move(message))
  {
  }
  ~ErrorResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mShortMessage && mMessage) {
      const Message &m = mMessage.value();
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"{}","message":"{}","body":{{"error":{}}}}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand,
        *mShortMessage,
        m);
    } else if (mShortMessage && !mMessage) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"{}","message":"{}"}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand,
        *mShortMessage);
    } else if (!mShortMessage && mMessage) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"{}","body":{{"error":{}}}}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand,
        *mMessage);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"{}"}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand);
    }
    return result;
  }

  SessionId mPid;
  std::string_view mCommand;
  std::optional<std::string> mShortMessage;
  std::optional<Message> mMessage;
};

struct PauseResponse final : ui::UIResult
{
  ~PauseResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"pause"}})",
        seq,
        mRequestSeq,
        mSessionId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"pause","message":"taskwasnotrunning"}})",
        seq,
        mRequestSeq,
        mSessionId);
    }
    return result;
  }
  PauseResponse(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}
};

struct Pause final : public ui::UICommand
{
  struct Args
  {
    int mThreadId;
  };

  Pause(UICommandArg arg, Args args) noexcept : UICommand(std::move(arg)), mPauseArgs(args) {}
  ~Pause() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);

    ASSERT(target, "No target {}", mSessionId);
    auto task = target->GetTaskByTid(mPauseArgs.mThreadId);
    if (task->IsStopped()) {
      return new PauseResponse{ false, this };
    }
    const bool success = target->SetAndCallRunAction(
      task->mTid, std::make_shared<ptracestop::StopImmediately>(*target, *task, StoppedReason::Pause));
    return new PauseResponse{ success, this };
  }

  Args mPauseArgs;
  DEFINE_NAME("pause");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct ReverseContinueResponse final : ui::UIResult
{
  ReverseContinueResponse(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {};
  ~ReverseContinueResponse() noexcept override = default;
  bool mContinueAll;
  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"reverseContinue","body":{{"allThreadsContinued":true}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        mContinueAll);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"reverseContinue","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mSessionId);
    }
    return result;
  }
};

/** ReverseContinue under RR is *always* "continue all"*/
struct ReverseContinue final : ui::UICommand
{
  ReverseContinue(UICommandArg arg, int threadId) noexcept : UICommand(std::move(arg)), mThreadId(threadId) {}
  ~ReverseContinue() noexcept override = default;
  int mThreadId;

  UIResultPtr
  Execute() noexcept final
  {
    auto res = new ReverseContinueResponse{ true, this };
    auto target = GetSupervisor();
    // TODO: This is the only command where it's ok to get a nullptr for target, in that case, we should just pick
    // _any_ target, and use that to resume backwards (since RR is the controller.).
    ASSERT(target, "must have target.");
    auto ok = target->ReverseResumeTarget(tc::ResumeAction{ .mResumeType = tc::RunType::Continue,
      .mResumeTarget = tc::ResumeTarget::AllNonRunningInProcess,
      .mDeliverSignal = 0 });
    res->mSuccess = ok;
    return res;
  }

  DEFINE_NAME("reverseContinue");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct ContinueResponse final : ui::UIResult
{
  CTOR(ContinueResponse);
  ~ContinueResponse() noexcept override = default;
  bool mContinueAll;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"continue","body":{{"allThreadsContinued":{}}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        mContinueAll);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"continue","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mSessionId);
    }
    return result;
  }
};

struct Continue final : public ui::UICommand
{
  int mThreadId;
  bool mContinueAll;

  Continue(UICommandArg arg, int tid, bool all) noexcept
      : UICommand(std::move(arg)), mThreadId(tid), mContinueAll(all)
  {
  }
  ~Continue() override = default;
  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);
    auto res = new ContinueResponse{ true, this };
    res->mContinueAll = mContinueAll;
    if (mContinueAll && !target->SomeTaskCanBeResumed()) {
      std::vector<Tid> running_tasks{};
      for (const auto &entry : target->GetThreads()) {
        if (!entry.mTask->IsStopped() || entry.mTask->mTracerVisibleStop) {
          running_tasks.push_back(entry.mTid);
        }
      }
      DBGLOG(core, "Denying continue request, target is running ([{}])", JoinFormatIterator{ running_tasks });
      res->mSuccess = false;
    } else {
      res->mSuccess = true;
      if (mContinueAll) {
        DBGLOG(core, "continue all");
        const int deliverNonSigtrapSignal = -1;
        target->ResumeTarget(tc::ResumeAction{
          tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess, deliverNonSigtrapSignal });
      } else {
        DBGLOG(core, "continue single thread: {}", mThreadId);
        auto t = target->GetTaskByTid(mThreadId);
        target->ResumeTask(*t, { tc::RunType::Continue, tc::ResumeTarget::Task, -1 });
      }
    }

    return res;
  }

  DEFINE_NAME("continue");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int }, { "sessionId", FieldType::Int });
};

struct NextResponse final : ui::UIResult
{
  CTOR(NextResponse);
  ~NextResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"next"}})",
        seq,
        mRequestSeq,
        mSessionId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"next","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mSessionId);
    }
    return result;
  }
};

struct Next final : public ui::UICommand
{
  int mThreadId;
  bool mContinueAll;
  SteppingGranularity granularity;

  Next(UICommandArg arg, int tid, bool all, SteppingGranularity granularity) noexcept
      : UICommand(std::move(arg)), mThreadId(tid), mContinueAll(all), granularity(granularity)
  {
  }
  ~Next() noexcept override = default;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);

    auto task = target->GetTaskByTid(mThreadId);

    if (!task->IsStopped()) {
      return new NextResponse{ false, this };
    }

    bool success = false;
    switch (granularity) {
    case SteppingGranularity::Instruction:
      success =
        target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::InstructionStep>(*target, *task, 1));
      break;
    case SteppingGranularity::Line:
      success = target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::LineStep>(*target, *task));
      break;
    case SteppingGranularity::LogicalBreakpointLocation:
      TODO("Next::execute granularity=SteppingGranularity::LogicalBreakpointLocation")
      break;
    }
    return new NextResponse{ success, this };
  }
  DEFINE_NAME("next");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct StepBackResponse final : ui::UIResult
{
  enum class Result : std::uint8_t
  {
    Success,
    NotStopped,
    NotReplaySession
  };
  StepBackResponse(Result result, UICommandPtr cmd) noexcept
      : UIResult(result == Result::Success, cmd), mResult(result) {};
  ~StepBackResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"stepBack"}})",
        seq,
        mRequestSeq,
        mSessionId);
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
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"stepBack","message":"{}"}})",
        seq,
        mRequestSeq,
        mSessionId,
        error);
    }
    return result;
  }

  Result mResult;
};

struct StepBack final : public ui::UICommand
{
  int mThreadId;

  StepBack(UICommandArg arg, int tid) noexcept : UICommand(std::move(arg)), mThreadId(tid) {}
  ~StepBack() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    auto target = GetSupervisor();
    ASSERT(target, "must have target");

    if (!target->IsReplaySession()) {
      return new StepBackResponse{ StepBackResponse::Result::NotReplaySession, this };
    } else if (target->IsRunning()) {
      // During reverse execution, because we are RR-oriented, the entire process will be stopped, so we don't have
      // to actually check individual tasks here.
      return new StepBackResponse{ StepBackResponse::Result::NotStopped, this };
    }

    target->ReverseResumeTarget(tc::ResumeAction{ .mResumeType = tc::RunType::Step,
      .mResumeTarget = tc::ResumeTarget::AllNonRunningInProcess,
      .mDeliverSignal = 0 });
    return new StepBackResponse{ StepBackResponse::Result::Success, this };
  }
  DEFINE_NAME("stepBack");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct StepInResponse final : ui::UIResult
{
  CTOR(StepInResponse);
  ~StepInResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"stepIn"}})",
        seq,
        mRequestSeq,
        mSessionId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"stepIn","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mSessionId);
    }
    return result;
  }
};

struct StepIn final : public ui::UICommand
{
  int mThreadId;
  bool mSingleThread;
  SteppingGranularity granularity;

  StepIn(UICommandArg arg, int threadId, bool singleThread, SteppingGranularity granularity) noexcept
      : UICommand(std::move(arg)), mThreadId(threadId), mSingleThread(singleThread), granularity(granularity)
  {
  }

  ~StepIn() noexcept final = default;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);

    auto task = target->GetTaskByTid(mThreadId);

    if (!task->IsStopped()) {
      return new StepInResponse{ false, this };
    }

    auto proceeder = ptracestop::StepInto::Create(*target, *task);

    if (!proceeder) {
      return new ErrorResponse{ Request,
        this,
        std::make_optional("No line table information could be found - abstract stepping not possible."),
        std::nullopt };
    }

    const bool success = target->SetAndCallRunAction(task->mTid, std::move(proceeder));
    return new StepInResponse{ success, this };
  }
  DEFINE_NAME("stepIn");
  RequiredArguments({ "threadId" });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct StepOutResponse final : ui::UIResult
{
  CTOR(StepOutResponse);
  ~StepOutResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"stepOut"}})",
        seq,
        mRequestSeq,
        mSessionId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"stepOut","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mSessionId);
    }
    return result;
  }
};

struct StepOut final : public ui::UICommand
{
  int thread_id;
  bool continue_all;

  StepOut(UICommandArg arg, int tid, bool all) noexcept
      : UICommand(std::move(arg)), thread_id(tid), continue_all(all)
  {
  }
  ~StepOut() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);
    auto task = target->GetTaskByTid(thread_id);

    if (!task->IsStopped()) {
      return new StepOutResponse{ false, this };
    }
    const auto req = CallStackRequest::partial(2);
    auto resume_addrs = task->UnwindReturnAddresses(target, req);
    ASSERT(resume_addrs.size() >= static_cast<std::size_t>(req.count), "Could not find frame info");
    const auto rip = resume_addrs[1];
    auto loc = target->GetOrCreateBreakpointLocation(rip);
    if (!loc.is_expected()) {
      return new StepOutResponse{ false, this };
    }
    auto user = target->GetUserBreakpoints().CreateBreakpointLocationUser<FinishBreakpoint>(
      *target, std::move(loc), task->mTid, task->mTid);
    bool success =
      target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::FinishFunction>(*target, *task, user));
    return new StepOutResponse{ success, this };
  }
  DEFINE_NAME("stepOut");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointRequestKind type) noexcept
      : ui::UIResult(success, cmd), mType(type)
  {
  }
  ~SetBreakpointsResponse() noexcept override = default;

  std::vector<ui::dap::Breakpoint> mBreakpoints{};
  BreakpointRequestKind mType;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(mdb::SystemPagesInBytes(1) / 2);
    auto outIt = std::back_inserter(result);
    std::pmr::vector<std::pmr::string> serializedBreakpoints{ arenaAllocator };
    serializedBreakpoints.reserve(mBreakpoints.size());
    for (auto &bp : mBreakpoints) {
      serializedBreakpoints.push_back(bp.Serialize(arenaAllocator));
    }
    switch (this->mType) {
    case BreakpointRequestKind::source:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"setBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    case BreakpointRequestKind::function:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"setFunctionBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    case BreakpointRequestKind::instruction:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"setInstructionBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    case BreakpointRequestKind::exception:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":{},"command":"setExceptionBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        mSuccess,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    default:
      PANIC("DAP doesn't expect Tracer breakpoints");
    }
    return result;
  }

  void
  AddBreakpoint(Breakpoint &&bp) noexcept
  {
    mBreakpoints.push_back(std::move(bp));
  }
};

struct SetBreakpoints final : public ui::UICommand
{
  SetBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept
      : ui::UICommand(std::move(arg)), args(arguments)
  {
    ASSERT(args.Contains("breakpoints") && args.UncheckedGetProperty("breakpoints")->IsArray(),
      "Arguments did not contain 'breakpoints' field or wasn't an array");
  }

  ~SetBreakpoints() override = default;

  mdbjson::JsonValue args;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);
    auto res = new SetBreakpointsResponse{ true, this, BreakpointRequestKind::source };

    ASSERT(args.Contains("source"), "setBreakpoints request requires a 'source' field");
    ASSERT(args.At("source")->Contains("path"), "source field requires a 'path' field");
    std::string_view file =
      args.UncheckedGetProperty("source")->UncheckedGetProperty("path")->UncheckedGetStringView();

    Set<BreakpointSpecification> srcBpSpecs;

    for (const auto &sourceBreakpoint : args.AsSpan("breakpoints")) {
      if (!sourceBreakpoint.Contains("line")) {
        DBGLOG(dap, "Source breakpoint requires a 'line' field");
        continue;
      }
      const u32 line = sourceBreakpoint["line"];
      auto column = get<u32>(sourceBreakpoint, "column");
      auto hitCondition = get<std::string>(sourceBreakpoint, "hitCondition");
      auto logMessage = get<std::string>(sourceBreakpoint, "logMessage");
      auto condition = get<std::string>(sourceBreakpoint, "condition");

      srcBpSpecs.insert(BreakpointSpecification::Create<SourceBreakpointSpecPair>(std::move(condition),
        std::move(hitCondition),
        std::string{ file },
        SourceBreakpointSpec{ .line = line, .column = column, .log_message = std::move(logMessage) }));
    }

    target->SetSourceBreakpoints(file, srcBpSpecs);

    using BP = ui::dap::Breakpoint;

    for (const auto &[bp, ids] : target->GetUserBreakpoints().GetBreakpointsFromSourceFile(file)) {
      for (const auto id : ids) {
        const auto user = target->GetUserBreakpoints().GetUserBreakpoint(id);
        res->AddBreakpoint(BP::CreateFromUserBreakpoint(*user));
      }
    }

    return res;
  }
  DEFINE_NAME("setBreakpoints");
  RequiredArguments({ "source"sv });
};

struct SetExceptionBreakpoints final : public ui::UICommand
{
  SetExceptionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &args) noexcept
      : ui::UICommand{ std::move(arg) }, mArgs(args)
  {
  }

  ~SetExceptionBreakpoints() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    DBGLOG(core, "exception breakpoints not yet implemented");
    auto res = new SetBreakpointsResponse{ true, this, BreakpointRequestKind::exception };
    return res;
  }

  mdbjson::JsonValue mArgs;

  DEFINE_NAME("setExceptionBreakpoints");
  RequiredArguments({ "filters"sv });
  DefineArgTypes({ "filters", FieldType::Array });
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept
      : UICommand{ std::move(arg) }, mArgs(arguments)
  {
    ASSERT(mArgs.Contains("breakpoints") && mArgs.At("breakpoints")->IsArray(),
      "Arguments did not contain 'breakpoints' field or wasn't an array");
  }

  ~SetInstructionBreakpoints() override = default;
  mdbjson::JsonValue mArgs;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);

    using BP = ui::dap::Breakpoint;
    Set<BreakpointSpecification> bps{};
    const auto ibps = mArgs.AsSpan("breakpoints");
    for (const auto &insBreakpoint : ibps) {
      ASSERT(
        insBreakpoint.Contains("instructionReference") && insBreakpoint.At("instructionReference")->IsString(),
        "instructionReference field not in args or wasn't of type string");
      std::string_view addrString = insBreakpoint["instructionReference"];
      bps.insert(BreakpointSpecification::Create<InstructionBreakpointSpec>({}, {}, std::string{ addrString }));
    }

    target->SetInstructionBreakpoints(bps);

    auto res = new SetBreakpointsResponse{ true, this, BreakpointRequestKind::instruction };
    auto &userBreakpoints = target->GetUserBreakpoints();
    res->mBreakpoints.reserve(userBreakpoints.mInstructionBreakpoints.size());

    for (const auto &[k, id] : userBreakpoints.mInstructionBreakpoints) {
      res->AddBreakpoint(BP::CreateFromUserBreakpoint(*userBreakpoints.GetUserBreakpoint(id)));
    }

    res->mSuccess = true;

    return res;
  }
  DEFINE_NAME("setInstructionBreakpoints");
  RequiredArguments({ "breakpoints"sv });
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept
      : UICommand{ std::move(arg) }, mArgs(arguments)
  {
    ASSERT(mArgs.Contains("breakpoints") && mArgs.At("breakpoints")->IsArray(),
      "Arguments did not contain 'breakpoints' field or wasn't an array");
  }

  ~SetFunctionBreakpoints() override = default;

  mdbjson::JsonValue mArgs;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);

    using BP = ui::dap::Breakpoint;
    Set<BreakpointSpecification> bkpts{};
    auto res = new SetBreakpointsResponse{ true, this, BreakpointRequestKind::function };
    for (const auto &fnbkpt : mArgs.AsSpan("breakpoints")) {
      ASSERT(fnbkpt.Contains("name") && fnbkpt["name"]->IsString(),
        "instructionReference field not in args or wasn't of type string");
      std::string functionName = fnbkpt["name"];
      bool isRegex = false;
      if (fnbkpt.Contains("regex")) {
        isRegex = fnbkpt["regex"];
      }

      bkpts.insert(
        BreakpointSpecification::Create<FunctionBreakpointSpec>({}, {}, std::move(functionName), isRegex));
    }

    target->SetFunctionBreakpoints(bkpts);
    for (const auto &user : target->GetUserBreakpoints().AllUserBreakpoints()) {
      if (user->mKind == LocationUserKind::Function) {
        res->AddBreakpoint(BP::CreateFromUserBreakpoint(*user));
      }
    }
    res->mSuccess = true;
    return res;
  }
  DEFINE_NAME("setFunctionBreakpoints");
  RequiredArguments({ "breakpoints"sv });
};

struct WriteMemoryResponse final : public ui::UIResult
{
  CTOR(WriteMemoryResponse);
  ~WriteMemoryResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":{},"command":"writeMemory","body":{{"bytesWritten":{}}}}})",
      seq,
      mRequestSeq,
      mSessionId,
      mSuccess,
      bytes_written);
    return result;
  }
  u64 bytes_written;
};

struct WriteMemory final : public ui::UICommand
{
  WriteMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset, std::vector<u8> &&bytes) noexcept
      : ui::UICommand(std::move(arg)), address(address), offset(offset), bytes(std::move(bytes))
  {
  }

  ~WriteMemory() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);
    PROFILE_SCOPE_ARGS("WriteMemory", "command", PEARG("seq", mSeq));
    auto response = new WriteMemoryResponse{ false, this };
    response->bytes_written = 0;
    if (address) {
      const auto result = target->GetInterface().WriteBytes(address.value(), bytes.data(), bytes.size());
      response->mSuccess = result.mWasSuccessful;
      if (result.mWasSuccessful) {
        response->bytes_written = result.uBytesWritten;
      }
    }

    return response;
  }

  std::optional<AddrPtr> address;
  int offset;
  std::vector<u8> bytes;

  DEFINE_NAME("writeMemory");
  RequiredArguments({ "memoryReference"sv, "data"sv });
  DefineArgTypes(
    { "memoryReference", FieldType::String }, { "data", FieldType::String }, { "offset", FieldType::Int });
};

struct ReadMemoryResponse final : public ui::UIResult
{
  CTOR(ReadMemoryResponse);
  ~ReadMemoryResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256 + mBase64Data.size());
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"readMemory","body":{{"address":"{}","unreadableBytes":{},"data":"{}"}}}})",
        seq,
        mRequestSeq,
        mSessionId,
        mFirstReadableAddress,
        mUnreadableBytes,
        mBase64Data);
    } else {
      TODO("non-success for ReadMemory");
    }
    return result;
  }
  AddrPtr mFirstReadableAddress;
  u64 mUnreadableBytes;
  std::pmr::string mBase64Data;
};

struct ReadMemory final : public ui::UICommand
{
  ReadMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept
      : UICommand{ std::move(arg) }, mAddress(address), mOffset(offset), mBytes(bytes)
  {
  }

  ~ReadMemory() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    if (mAddress) {
      PROFILE_SCOPE_ARGS(
        "ReadMemory", "command", PEARG("seq", mSeq), PEARG("addr", *mAddress), PEARG("bytes", mBytes));
      GetOrSendError(target);
      auto sv = target->ReadToVector(*mAddress, mBytes, mDAPClient->GetResponseArenaAllocator());
      auto res = new ReadMemoryResponse{ true, this };
      res->mBase64Data = mdb::EncodeIntoBase64(sv->span(), mDAPClient->GetResponseArenaAllocator());
      res->mFirstReadableAddress = *mAddress;
      res->mSuccess = true;
      res->mUnreadableBytes = 0;
      return res;
    } else {
      return new ErrorResponse{ Request, this, "Address parameter could not be parsed.", std::nullopt };
    }
  }

  std::optional<AddrPtr> mAddress;
  int mOffset;
  u64 mBytes;

  DEFINE_NAME("readMemory");
  RequiredArguments({ "memoryReference"sv, "count"sv });
  DefineArgTypes(
    { "memoryReference", FieldType::Address }, { "count", FieldType::Int }, { "offset", FieldType::Int });
};

struct ConfigurationDoneResponse final : public ui::UIResult
{
  CTOR(ConfigurationDoneResponse);
  ~ConfigurationDoneResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    result.reserve(256);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"configurationDone"}})",
      seq,
      mRequestSeq,
      mSessionId);
    return result;
  }
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}

  ~ConfigurationDone() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    return new ConfigurationDoneResponse{ true, this };
  }

  DEFINE_NAME("configurationDone");
  NoRequiredArgs();
};

struct DisconnectResponse final : public UIResult
{
  CTOR(DisconnectResponse);
  ~DisconnectResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"disconnect"}})",
      seq,
      mRequestSeq,
      mSessionId);
    return result;
  }
};

struct Disconnect final : public UICommand
{
  Disconnect(UICommandArg arg, bool restart, bool terminateDebuggee, bool suspendDebuggee) noexcept
      : UICommand{ std::move(arg) }, mRestart(restart), mTerminateTracee(terminateDebuggee),
        mSuspendTracee(suspendDebuggee)
  {
  }

  ~Disconnect() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    // We don't allow for child sessions to be terminated, and not have the entire application torn down.
    // We only allow for suspension, or detaching individual child sessions. This behavior is also mimicked for RR
    // sessions, as destroying a process would invalidate the entire application trace.
    GetOrSendError(target);

    if (mTerminateTracee || mDAPClient->mSessionType == DapClientSession::Launch) {
      Tracer::Get().TerminateSession();
    } else {
      target->Disconnect();
    }
    mDAPClient->PushDelayedEvent(new DisconnectResponse{ true, this });
    mDAPClient->PushDelayedEvent(new TerminatedEvent{ mSessionId });
    return nullptr;
  }

  bool mRestart, mTerminateTracee, mSuspendTracee;
  DEFINE_NAME("disconnect");
  NoRequiredArgs();
};

struct InitializeResponse final : public ui::UIResult
{
  CTOR(InitializeResponse);
  InitializeResponse(bool rrsession, bool ok, UICommandPtr cmd) noexcept : UIResult(ok, cmd), RRSession(rrsession)
  {
  }
  ~InitializeResponse() noexcept override = default;

  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  std::string mSessionId;
  bool RRSession;
};

struct Initialize final : public ui::UICommand
{
  Initialize(UICommandArg arg, mdbjson::JsonValue arguments) noexcept
      : UICommand{ std::move(arg) }, mArgs(arguments)
  {
  }

  ~Initialize() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    DBGLOG(core, "Executing initialize request, session id={}", mSessionId);
    bool RRSession = false;
    if (mArgs.Contains("RRSession") && mArgs["RRSession"]->IsBoolean()) {
      RRSession = mArgs["RRSession"];
    }

    mDAPClient->AddSupervisor(Tracer::PrepareNewSupervisorWithId(mSessionId));
    mDAPClient->PushDelayedEvent(new ui::dap::InitializedEvent{ mSessionId, {} });
    return new InitializeResponse{ RRSession, true, this };
  }
  mdbjson::JsonValue mArgs;
  DEFINE_NAME("initialize");
  NoRequiredArgs();
};

std::pmr::string
InitializeResponse::Serialize(int, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  // "this _must_ be 1, the first response"

  auto body = std::format(R"({{ "supportsConfigurationDoneRequest": true,
  "supportsFunctionBreakpoints": true,
  "supportsConditionalBreakpoints": true,
  "supportsHitConditionalBreakpoints": true,
  "supportsEvaluateForHovers": false,
  "supportsStepBack": {},
  "supportsSingleThreadExecutionRequests": {},
  "supportsSetVariable": false,
  "supportsRestartFrame": false,
  "supportsGotoTargetsRequest": false,
  "supportsStepInTargetsRequest": false,
  "supportsCompletionsRequest": false,
  "completionTriggerCharacters": [ ".", "[" ],
  "supportsModulesRequest": false,
  "additionalModuleColumns": false,
  "supportedChecksumAlgorithms": false,
  "supportsRestartRequest": false,
  "supportsExceptionOptions": false,
  "supportsValueFormattingOptions": true,
  "supportsExceptionInfoRequest": false,
  "supportTerminateDebuggee": false,
  "supportSuspendDebuggee": false,
  "supportsDelayedStackTraceLoading": false,
  "supportsLoadedSourcesRequest": false,
  "supportsLogPoints": true,
  "supportsTerminateThreadsRequest": true,
  "supportsVariableType": true,
  "supportsSetExpression": false,
  "supportsTerminateRequest": true,
  "supportsDataBreakpoints": false,
  "supportsReadMemoryRequest": true,
  "supportsWriteMemoryRequest": true,
  "supportsDisassembleRequest": true,
  "supportsCancelRequest": false,
  "supportsBreakpointLocationsRequest": false,
  "supportsSteppingGranularity": true,
  "supportsInstructionBreakpoints": true,
  "supportsExceptionFilterOptions": false }})",
    RRSession,
    !RRSession);

  std::pmr::string res{ arenaAllocator };

  std::format_to(std::back_inserter(res),
    R"({{"seq":0,"request_seq":{},"sessionId":0,"type":"response","success":true,"command":"initialize","body": {} }})",
    mRequestSeq,
    body);
  return res;
}

struct LaunchResponse final : public UIResult
{
  LaunchResponse(SessionId sessionId, std::optional<SessionId> newProcess, bool success, UICommandPtr cmd) noexcept
      : UIResult{ success, cmd }, mProcessId{ newProcess }, mRequestingSessionId{ sessionId } {};
  ~LaunchResponse() noexcept override = default;

  std::optional<SessionId> mProcessId;
  SessionId mRequestingSessionId;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    VERIFY(mProcessId.has_value(), "Failed to launch binary, but not responding with ErrorResponse?");

    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"launch", "body": {{ "processId": {}}}}})",
      seq,
      mRequestSeq,
      mRequestingSessionId,
      *mProcessId);
    return result;
  }
};

struct Launch final : public UICommand
{
  Launch(UICommandArg arg,
    SessionId id,
    bool stopOnEntry,
    Path program,
    std::pmr::vector<std::pmr::string> &&program_args,
    std::optional<BreakpointBehavior> breakpointBehavior) noexcept
      : UICommand{ std::move(arg) }, mStopOnEntry{ stopOnEntry }, mProgram{ std::move(program) },
        mProgramArgs{ std::move(program_args) }, mBreakpointBehavior{ breakpointBehavior },
        mRequestingSessionId{ id }
  {
  }

  ~Launch() noexcept override = default;

  UIResultPtr
  Execute() noexcept final
  {
    PROFILE_SCOPE_ARGS(
      "launch", "command", PEARG("program", mProgram), PEARG("progArgs", std::span{ mProgramArgs }));
    const auto processId =
      Tracer::Launch(mDAPClient, mRequestingSessionId, mStopOnEntry, mProgram, mProgramArgs, mBreakpointBehavior);
    GetOrSendError(supervisor);
    supervisor->ConfigurationDone();
    DBGLOG(core, "Responding to launch request, resuming target {}", supervisor->TaskLeaderTid());
    supervisor->ResumeTarget(
      tc::ResumeAction{ tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess, 0 });
    return new LaunchResponse{ mRequestingSessionId, processId, true, this };
  }
  bool mStopOnEntry;
  Path mProgram;
  std::pmr::vector<std::pmr::string> mProgramArgs;
  std::optional<BreakpointBehavior> mBreakpointBehavior;
  SessionId mRequestingSessionId;
  DEFINE_NAME("launch");
  RequiredArguments({ "program"sv });
  DefineArgTypes({ "program", FieldType::String });
};

struct AttachResponse final : public UIResult
{
  AttachResponse(SessionId processId, bool success, UICommandPtr cmd) noexcept
      : UIResult(success, cmd), mProcessId(processId)
  {
  }
  ~AttachResponse() noexcept override = default;
  SessionId mProcessId;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"attach"}})",
      seq,
      mRequestSeq,
      mSessionId);
    return result;
  }
};

struct Attach final : public UICommand
{
  Attach(UICommandArg arg, SessionId sessionId, AttachArgs args) noexcept
      : UICommand{ std::move(arg) }, mRequestingSessionId{ sessionId }, attachArgs{ args }
  {
  }

  ~Attach() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    const auto processId = Tracer::Get().Attach(mDAPClient, mRequestingSessionId, attachArgs);
    GetOrSendError(supervisor);
    if (supervisor->IsReplaySession()) {
      supervisor->ResumeTarget(
        tc::ResumeAction{ tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess, 0 });
    } else {
      DBGLOG(core, "configurationDone - doing nothing for normal attach sessions {}", supervisor->TaskLeaderTid());
    }
    return new AttachResponse{ processId, true, this };
  }

  SessionId mRequestingSessionId;
  AttachArgs attachArgs;
  DEFINE_NAME("attach");
  RequiredArguments({ "type"sv });

  DefineArgTypes({ "port", FieldType::Int },
    { "host", FieldType::String },
    { "pid", FieldType::Int },
    {
      "type",
      FieldType::Enumeration,
      { "ptrace"sv, "gdbremote"sv, "rr"sv, "auto"sv },
    });

  static ui::UICommand *
  create(UICommandArg arg, const mdbjson::JsonValue &args) noexcept
  {
    auto type = args.At("type")->UncheckedGetStringView();
    ASSERT(args.Contains("sessionId"), "Attach arguments had no 'sessionId' field.");
    if (type == "ptrace") {
      SessionId pid = args["pid"];
      return new Attach{ std::move(arg), args["sessionId"], PtraceAttachArgs{ .pid = pid } };
    } else if (type == "auto") {
      SessionId processId;
      if (args.Contains("processId")) {
        processId = args["processId"];
        return new Attach{ std::move(arg), args["sessionId"], AutoArgs{ processId } };
      }
      return new ui::dap::InvalidArgs{ std::move(arg),
        "attach",
        std::vector<InvalidArg>{ { ArgumentError::Missing("Required for auto attach"), "processId" } } };
    } else {
      int port = args["port"];
      std::string_view host = args["host"];
      bool allstop = true;
      if (auto allStopVal = args.At("allstop"); allStopVal && allStopVal->IsBoolean()) {
        allstop = allStopVal->UncheckedGetBoolean();
      }
      RemoteType remote_type = type == "rr" ? RemoteType::RR : RemoteType::GDB;

      return new Attach{ std::move(arg),
        args["sessionId"],
        GdbRemoteAttachArgs{ .host = host, .port = port, .allstop = allstop, .type = remote_type } };
    };
  }
};

struct TerminateResponse final : public UIResult
{
  CTOR(TerminateResponse);
  ~TerminateResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"terminate"}})",
      seq,
      mRequestSeq,
      mSessionId);
    return result;
  }
};

struct Terminate final : public UICommand
{
  Terminate(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~Terminate() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    Tracer::Get().TerminateSession();
    return new TerminateResponse{ true, this };
  }
  DEFINE_NAME("terminate");
  NoRequiredArgs();
};

struct ThreadsResponse final : public UIResult
{
  ThreadsResponse(bool success, std::pmr::vector<Thread> &&threads, UICommandPtr cmd) noexcept
      : UIResult(success, cmd), mThreads(std::move(threads)) {};

  ~ThreadsResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256 + (mThreads.size() * 64));
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"threads","body":{{"threads":[{}]}}}})",
      seq,
      mRequestSeq,
      mSessionId,
      JoinFormatIterator{ mThreads, "," });
    return result;
  }

  std::pmr::vector<Thread> mThreads;
};

struct Threads final : public UICommand
{
  Threads(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~Threads() override = default;

  UIResultPtr
  Execute() noexcept final
  {
    GetOrSendError(target);

    std::pmr::vector<Thread> threads{ mCommandAllocator->GetAllocator() };
    auto &it = target->GetInterface();

    if (it.mFormat == TargetFormat::Remote) {
      auto res =
        it.RemoteConnection()->QueryTargetThreads({ target->TaskLeaderTid(), target->TaskLeaderTid() }, false);
      ASSERT(res.front().pid == target->TaskLeaderTid(), "expected pid == task_leader");
      for (const auto thr : res) {
        if (std::ranges::none_of(
              target->GetThreads(), [t = thr.tid](const auto &entry) { return entry.mTid == t; })) {
          target->AddTask(TaskInfo::CreateTask(target->GetInterface(), thr.tid, false));
        }
      }
      target->RemoveTasksNotInSet(res);
    }

    auto knownThreads = target->GetThreads();
    threads.reserve(knownThreads.size());
    for (const auto &entry : knownThreads) {
      const auto tid = entry.mTid;
      threads.push_back(Thread{ .mThreadId = tid, .mName = it.GetThreadName(tid) });
    }
    return new ThreadsResponse{ true, std::move(threads), this };
  }
  DEFINE_NAME("threads");
  NoRequiredArgs();
};

struct StackTrace final : public UICommand
{
  StackTrace(UICommandArg arg,
    int threadId,
    std::optional<int> startFrame,
    std::optional<int> levels,
    std::optional<StackTraceFormat> format) noexcept;
  ~StackTrace() override = default;
  UIResultPtr Execute() noexcept final;
  int mThreadId;
  std::optional<int> mStartFrame;
  std::optional<int> mLevels;
  std::optional<StackTraceFormat> mFormat;
  DEFINE_NAME("stackTrace");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct StackTraceResponse final : public UIResult
{
  CTOR(StackTraceResponse);
  StackTraceResponse(bool success, StackTrace *cmd, std::vector<StackFrame> stack_frames) noexcept;
  ~StackTraceResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::vector<StackFrame> stack_frames;
};

StackTrace::StackTrace(UICommandArg arg,
  int threadId,
  std::optional<int> startFrame,
  std::optional<int> levels,
  std::optional<StackTraceFormat> format) noexcept
    : UICommand{ std::move(arg) }, mThreadId(threadId), mStartFrame(startFrame), mLevels(levels), mFormat(format)
{
}

StackTraceResponse::StackTraceResponse(
  bool success, StackTrace *cmd, std::vector<StackFrame> stack_frames) noexcept
    : UIResult(success, cmd), stack_frames(std::move(stack_frames))
{
}

std::pmr::string
StackTraceResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  // Estimated size per stack frame; 105 for the formatting string, 18 for the address, 2+2 for line:col, 256 for
  // name and path
  // + format string for response with some additional spill.
  result.reserve(256 + ((105 + 18 + 2 + 2 + 256) * stack_frames.size()));
  auto outIt = std::back_inserter(result);
  std::format_to(outIt,
    R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"stackTrace","body":{{"stackFrames":[{}]}}}})",
    seq,
    mRequestSeq,
    mSessionId,
    JoinFormatIterator{ stack_frames, "," });
  return result;
}

UIResultPtr
StackTrace::Execute() noexcept
{
  // todo(simon): multiprocessing needs additional work, since DAP does not support it natively.
  GetOrSendError(target);
  PROFILE_BEGIN_ARGS("StackTrace", "command", PEARG("seq", mSeq));
  auto task = target->GetTaskByTid(mThreadId);
  if (task == nullptr) {
    return new ErrorResponse{
      StackTrace::Request, this, std::format("Thread with ID {} not found", mThreadId), {}
    };
  }
  auto &cfs = target->BuildCallFrameStack(*task, CallStackRequest::full());
  std::vector<StackFrame> stackFrames{};
  stackFrames.reserve(cfs.FramesCount());
  for (auto &frame : cfs.GetFrames()) {
    if (frame.GetFrameType() == sym::FrameType::Full) {
      const auto [src, lte] = frame.GetLineTableEntry();
      if (src && lte) {
        stackFrames.push_back(StackFrame{ .mVariablesReference = frame.FrameId(),
          .mName = frame.Name().value_or("unknown"),
          .mSource = Source{ .name = src->mFullPath.StringView(), .path = src->mFullPath.StringView() },
          .mLine = static_cast<int>(lte->line),
          .mColumn = static_cast<int>(lte->column),
          .mProgramCounter = std::format("{}", frame.FramePc()) });
      } else if (src) {
        stackFrames.push_back(StackFrame{ .mVariablesReference = frame.FrameId(),
          .mName = frame.Name().value_or("unknown"),
          .mSource = Source{ .name = src->mFullPath.StringView(), .path = src->mFullPath.StringView() },
          .mLine = 0,
          .mColumn = 0,
          .mProgramCounter = std::format("{}", frame.FramePc()) });
      } else {
        stackFrames.push_back(StackFrame{ .mVariablesReference = frame.FrameId(),
          .mName = frame.Name().value_or("unknown"),
          .mSource = std::nullopt,
          .mLine = 0,
          .mColumn = 0,
          .mProgramCounter = std::format("{}", frame.FramePc()) });
      }

    } else {
      stackFrames.push_back(StackFrame{ .mVariablesReference = frame.FrameId(),
        .mName = frame.Name().value_or("unknown"),
        .mSource = std::nullopt,
        .mLine = 0,
        .mColumn = 0,
        .mProgramCounter = std::format("{}", frame.FramePc()) });
    }
  }
  PROFILE_END_ARGS("StackTrace", "command", PEARG("frames", stackFrames.size()));
  return new StackTraceResponse{ true, this, std::move(stackFrames) };
}

struct ScopesResponse final : public UIResult
{
  ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept;
  ~ScopesResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256 + (256 * mScopes.size()));
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"scopes","body":{{"scopes":[{}]}}}})",
      seq,
      mRequestSeq,
      mSessionId,
      JoinFormatIterator{ mScopes, "," });
    return result;
  }

  // For now, we only have 3 scopes, Args, Locals, Registers
  std::array<Scope, 3> mScopes;
};

struct Scopes final : public UICommand
{
  Scopes(UICommandArg arg, int frameId) noexcept : UICommand{ std::move(arg) }, mFrameId(frameId) {}
  ~Scopes() noexcept override = default;

  UIResultPtr
  Execute() noexcept final
  {
    auto ctx = Tracer::Get().GetVariableContext(mFrameId);
    if (!ctx || !ctx->IsValidContext() || ctx->mType != ContextType::Frame) {
      return new ErrorResponse{ Request, this, std::format("Invalid variable context for {}", mFrameId), {} };
    }
    auto frame = ctx->GetFrame(mFrameId);
    if (!frame) {
      return new ScopesResponse{ false, this, {} };
    }
    const auto scopes = frame->Scopes();
    return new ScopesResponse{ true, this, scopes };
  }

  int mFrameId;
  DEFINE_NAME("scopes");
  RequiredArguments({ "frameId"sv });
  DefineArgTypes({ "frameId", FieldType::Int });
};

ScopesResponse::ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept
    : UIResult(success, cmd), mScopes(scopes)
{
}

struct DisassembleResponse final : public UIResult
{
  CTOR(DisassembleResponse);
  ~DisassembleResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::vector<sym::Disassembly> mInstructions;
};

struct Disassemble final : public UICommand
{
  Disassemble(UICommandArg arg,
    std::optional<AddrPtr> address,
    int byteOffset,
    int instructionOffset,
    int instructionCount,
    bool resolveSymbols) noexcept;
  ~Disassemble() noexcept override = default;
  UIResultPtr Execute() noexcept final;

  std::optional<AddrPtr> mAddress;
  int mByteOffset;
  int mInstructionOffset;
  int ins_count;
  bool mResolveSymbols;
  DEFINE_NAME("disassemble");
  RequiredArguments({ "memoryReference", "instructionCount" });
  DefineArgTypes({ "memoryReference", FieldType::String },
    { "instructionCount", FieldType::Int },
    { "instructionOffset", FieldType::Int },
    { "offset", FieldType::Int });
};

Disassemble::Disassemble(UICommandArg arg,
  std::optional<AddrPtr> address,
  int byteOffset,
  int instructionOffset,
  int instructionCount,
  bool resolveSymbols) noexcept
    : UICommand{ std::move(arg) }, mAddress(address), mByteOffset(byteOffset),
      mInstructionOffset(instructionOffset), ins_count(instructionCount), mResolveSymbols(resolveSymbols)
{
}

UIResultPtr
Disassemble::Execute() noexcept
{
  if (mAddress) {
    GetOrSendError(target);
    auto res = new DisassembleResponse{ true, this };
    res->mInstructions.reserve(ins_count);
    int remaining = ins_count;
    if (mInstructionOffset < 0) {
      const int negative_offset = std::abs(mInstructionOffset);
      sym::DisassembleBackwards(target, mAddress.value(), static_cast<u32>(negative_offset), res->mInstructions);
      if (negative_offset < ins_count) {
        for (auto i = 0u; i < res->mInstructions.size(); i++) {
          if (res->mInstructions[i].address == mAddress) {
            keep_range(res->mInstructions, i - negative_offset, i);
            break;
          }
        }
      } else {
        for (auto i = 0u; i < res->mInstructions.size(); i++) {
          if (res->mInstructions[i].address == mAddress) {
            keep_range(res->mInstructions, i - negative_offset, i - negative_offset + ins_count);
            break;
          }
        }
        return res;
      }
      remaining -= res->mInstructions.size();
      mInstructionOffset = 0;
    }

    if (remaining > 0) {
      sym::Disassemble(
        target, mAddress.value(), static_cast<u32>(std::abs(mInstructionOffset)), remaining, res->mInstructions);
    }
    return res;
  } else {
    return new ErrorResponse{ Request, this, "Address parameter could not be parsed.", std::nullopt };
  }
}

std::pmr::string
DisassembleResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  result.reserve(256 + (256 * mInstructions.size()));
  auto outIt = std::back_inserter(result);
  auto it = std::format_to(outIt,
    R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"disassemble","body":{{"instructions":[)",
    seq,
    mRequestSeq,
    mSessionId);
  auto count = 0;
  for (const auto &inst : mInstructions) {
    if (count > 0) {
      *it++ = ',';
    }
    it = std::format_to(it, R"({})", inst);
    count++;
  }
  it = std::format_to(it, R"(]}}}})");
  return result;
}

struct Evaluate final : public UICommand
{
  Evaluate(UICommandArg arg,
    std::string expression,
    std::optional<int> frameId,
    std::optional<EvaluationContext> context) noexcept;
  ~Evaluate() noexcept final = default;
  UIResultPtr Execute() noexcept final;

  Immutable<std::string> expr;
  Immutable<std::optional<int>> frameId;
  Immutable<EvaluationContext> context;

  DEFINE_NAME("evaluate");
  RequiredArguments({ "expression"sv, "context"sv });
  DefineArgTypes(
    { "expression", FieldType::String }, { "frameId", FieldType::Int }, { "context", FieldType::String });

  static EvaluationContext ParseContext(std::string_view input) noexcept;
  static UICommand *PrepareEvaluateCommand(UICommandArg arg, const mdbjson::JsonValue &args);
};

struct EvaluateResponse final : public UIResult
{
  EvaluateResponse(bool success,
    Evaluate *cmd,
    std::optional<int> variablesReference,
    std::pmr::string *result,
    std::optional<std::string> &&type,
    std::optional<std::string> &&memoryReference) noexcept;
  ~EvaluateResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  std::pmr::string *mResult;
  std::optional<std::string> mType;
  int mVariablesReference;
  std::optional<std::string> mMemoryReference;
};

Evaluate::Evaluate(UICommandArg arg,
  std::string expression,
  std::optional<int> frameId,
  std::optional<EvaluationContext> context) noexcept
    : UICommand{ std::move(arg) }, expr(std::move(expression)), frameId(frameId),
      context(context.value_or(EvaluationContext::Watch))
{
}

UIResultPtr
Evaluate::Execute() noexcept
{
  PROFILE_SCOPE_ARGS("Evaluate", "command", PEARG("seq", mSeq));
  switch (context) {
  case EvaluationContext::Watch:
    [[fallthrough]];
  case EvaluationContext::Repl: {
    Allocator alloc{ mDAPClient->GetResponseArenaAllocator() };
    auto result = Tracer::Get().EvaluateDebugConsoleExpression(expr, &alloc);
    return new EvaluateResponse{ true, this, {}, result, {}, {} };
  }
  case EvaluationContext::Hover:
    [[fallthrough]];
  case EvaluationContext::Clipboard:
    [[fallthrough]];
  case EvaluationContext::Variables:
    return new ErrorResponse{ Request, this, {}, Message{ .format = "could not evaluate" } };
  }
}

EvaluationContext
Evaluate::ParseContext(std::string_view input) noexcept
{

  static constexpr auto contexts = { std::pair{ "watch", EvaluationContext::Watch },
    std::pair{ "repl", EvaluationContext::Repl },
    std::pair{ "hover", EvaluationContext::Hover },
    std::pair{ "clipboard", EvaluationContext::Clipboard },
    std::pair{ "variables", EvaluationContext::Variables } };

  for (const auto &[k, v] : contexts) {
    if (k == input) {
      return v;
    }
  }

  return EvaluationContext::Repl;
}

/*static*/
UICommand *
Evaluate::PrepareEvaluateCommand(UICommandArg arg, const mdbjson::JsonValue &args)
{
  IfInvalidArgsReturn(Evaluate);

  std::string expr = args["expression"];
  std::optional<int> frameId{};
  EvaluationContext ctx{};
  if (args.Contains("frameId")) {
    frameId = args["frameId"];
  }

  std::string_view context = args["context"];
  ctx = Evaluate::ParseContext(context);

  return new ui::dap::Evaluate{ std::move(arg), std::move(expr), frameId, ctx };
}

EvaluateResponse::EvaluateResponse(bool success,
  Evaluate *cmd,
  std::optional<int> variablesReference,
  std::pmr::string *evalResult,
  std::optional<std::string> &&type,
  std::optional<std::string> &&memoryReference) noexcept
    : UIResult(success, cmd), mResult(evalResult), mType(std::move(type)),
      mVariablesReference(variablesReference.value_or(0)), mMemoryReference(std::move(memoryReference))
{
}

std::pmr::string
EvaluateResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string evalResponseResult{ arenaAllocator };
  evalResponseResult.reserve(1024);
  if (mSuccess) {
    std::format_to(std::back_inserter(evalResponseResult),
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"evaluate","body":{{ "result":"{}", "variablesReference":{} }}}})",
      seq,
      mRequestSeq,
      mSessionId,
      DebugAdapterProtocolString{ *mResult },
      mVariablesReference);
  } else {
    std::format_to(std::back_inserter(evalResponseResult),
      R"({{"seq":0,"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"evaluate","body":{{ "error":{{ "id": -1, "format": "{}" }} }}}})",
      mRequestSeq,
      mSessionId,
      mSuccess,
      DebugAdapterProtocolString{ *mResult });
  }
  return evalResponseResult;
}

struct Variables final : public UICommand
{
  Variables(
    UICommandArg arg, VariableReferenceId varRef, std::optional<u32> start, std::optional<u32> count) noexcept;
  ~Variables() override = default;
  UIResultPtr Execute() noexcept final;
  ErrorResponse *error(std::string &&msg) noexcept;
  VariableReferenceId mVariablesReferenceId;
  std::optional<u32> mStart;
  std::optional<u32> mCount;
  DEFINE_NAME("variables");
  RequiredArguments({ "variablesReference"sv });
  DefineArgTypes(
    { "variablesReference", FieldType::Int }, { "start", FieldType::Int }, { "count", FieldType::Int });
};

struct VariablesResponse final : public UIResult
{
  VariablesResponse(bool success, Variables *cmd, std::vector<Ref<sym::Value>> &&vars) noexcept;
  ~VariablesResponse() noexcept override;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  int mRequestedReference;
  std::vector<Ref<sym::Value>> mVariables;
};

Variables::Variables(
  UICommandArg arg, VariableReferenceId var_ref, std::optional<u32> start, std::optional<u32> count) noexcept
    : UICommand{ std::move(arg) }, mVariablesReferenceId(var_ref), mStart(start), mCount(count)
{
}

ErrorResponse *
Variables::error(std::string &&msg) noexcept
{
  return new ErrorResponse{
    Request, this, {}, Message{ .format = std::move(msg), .variables = {}, .show_user = true }
  };
}

UIResultPtr
Variables::Execute() noexcept
{
  PROFILE_SCOPE_ARGS("Variables", "command", PEARG("seq", mSeq));
  auto requestedContext = Tracer::Get().GetVariableContext(mVariablesReferenceId);
  if (!requestedContext || !requestedContext->IsValidContext()) {
    return error(std::format("Could not find variable with variablesReference {}", mVariablesReferenceId));
  }
  auto &context = *requestedContext;
  auto frame = context.GetFrame(mVariablesReferenceId);
  if (!frame) {
    return error(
      std::format("Could not find frame that's referenced via variablesReference {}", mVariablesReferenceId));
  }

  switch (context.mType) {
  case ContextType::Frame:
    return error(
      std::format("Sent a variables request using a reference for a frame is an error.", mVariablesReferenceId));
  case ContextType::Scope: {
    auto scope = frame->Scope(mVariablesReferenceId);
    switch (scope->type) {
    case ScopeType::Arguments: {
      auto vars =
        context.mSymbolFile->GetVariables(*context.mTask->GetSupervisor(), *frame, sym::VariableSet::Arguments);
      return new VariablesResponse{ true, this, std::move(vars) };
    }
    case ScopeType::Locals: {
      auto vars =
        context.mSymbolFile->GetVariables(*context.mTask->GetSupervisor(), *frame, sym::VariableSet::Locals);
      return new VariablesResponse{ true, this, std::move(vars) };
    }
    case ScopeType::Registers: {
      return new VariablesResponse{ true, this, {} };
    } break;
    }
  } break;
  case ContextType::Variable:
    return new VariablesResponse{ true, this, context.mSymbolFile->ResolveVariable(context, mStart, mCount) };
  case ContextType::Global:
    TODO("Global variables not yet implemented support for");
    break;
  }

  return error(std::format("Could not find variable with variablesReference {}", mVariablesReferenceId));
}

VariablesResponse::VariablesResponse(bool success, Variables *cmd, std::vector<Ref<sym::Value>> &&vars) noexcept
    : UIResult(success, cmd), mRequestedReference(cmd != nullptr ? cmd->mVariablesReferenceId : 0),
      mVariables(std::move(vars))
{
}

VariablesResponse::~VariablesResponse() noexcept = default;

std::pmr::string
VariablesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  PROFILE_SCOPE_ARGS("VariablesResponse", "command", PEARG("seq", int64_t{ seq }));
  std::pmr::string result{ arenaAllocator };
  result.reserve(256 + (256 * mVariables.size()));
  if (mVariables.empty()) {
    std::format_to(std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"variables","body":{{"variables":[]}}}})",
      seq,
      mRequestSeq,
      mSessionId);
    return result;
  }
  std::pmr::string variables_contents{ arenaAllocator };
  variables_contents.reserve(256 * variables_contents.size());
  auto it = std::back_inserter(variables_contents);
  for (const auto &v : mVariables) {
    if (auto datvis = v->GetVisualizer(); datvis != nullptr) {

      auto opt = datvis->Serialize(*v, v->mName, v->ReferenceId(), arenaAllocator);
      if (opt) {
        it = std::format_to(it, "{},", *opt);
      } else {
        std::format_to(std::back_inserter(result),
          R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":false,"command":"variables","message":"visualizer failed","body":{{"error":{{"id": -1, "format": "Could not visualize value for '{}'"}} }} }})",
          seq,
          mRequestSeq,
          mSessionId,
          v->mName);
        return result;
      }
    } else {
      ASSERT(v->GetType()->IsReference(),
        "Add visualizer & resolver for T* types. It will look more "
        "or less identical to CStringResolver & ArrayResolver");
      // Todo: this seem particularly shitty. For many reasons. First we check if there's a visualizer, then we
      // do individual type checking again.
      //  this should be streamlined, to be handled once up front. We also need some way to create "new" types.
      auto span = v->MemoryView();
      const std::uintptr_t ptr = sym::BitCopy<std::uintptr_t>(span);
      auto ptr_str = std::format("0x{:x}", ptr);
      const std::string_view name = v->mName.StringView();
      it = std::format_to(it,
        R"({{ "name": "{}", "value": "{}", "type": "{}", "variablesReference": {}, "memoryReference": "{}" }},)",
        name,
        ptr_str,
        *v->GetType(),
        v->ReferenceId(),
        v->Address());
    }
  }

  variables_contents.pop_back();

  std::format_to(std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"sessionId":{},"type":"response","success":true,"command":"variables","body":{{"variables":[{}]}}}})",
    seq,
    mRequestSeq,
    mSessionId,
    variables_contents);
  return result;
}

static bool
ValidateRequestFormat(const mdbjson::JsonValue &req) noexcept
{
  const auto missingFields = req.Contains("command") && req.Contains("type") && req.Contains("seq") &&
                             req.Contains("arguments") && req.Contains(kSessionId);
  if (!missingFields) {
    DBGLOG(core, "Request missing fields. Request: {}", req);
    return false;
  }

  const auto correctTypes = req["command"]->IsString() && req["seq"]->IsNumber() && req[kSessionId]->IsNumber();

  if (!correctTypes) {
    DBGLOG(dap, "Base protocol request fields of incorrect type. Request: {}", req);
    return false;
  }

  return true;
}

ui::UICommand *
ParseDebugAdapterCommand(DebugAdapterClient &client, std::string_view packet) noexcept
{
  using namespace ui::dap;

  UICommandArg arg{ 0, 0, client.AcquireArena() };
  std::pmr::string *str = arg.allocator->Allocate<std::pmr::string>();
  str->reserve(packet.size());
  // now we've stored the data in the block. it'll live as long as the allocator is alive.
  str->append(packet);

  const auto jsonResult = mdbjson::Parse(*arg.allocator, *str);

  if (!jsonResult) {
    return nullptr;
  }

  const auto &obj = jsonResult.value();
  if (!ValidateRequestFormat(obj)) {
    return nullptr;
  }

  DBGLOG(core, "[dap]: parsed request: {}", obj);
  std::string_view commandName = obj["command"];

  arg.mSeq = obj["seq"];
  arg.mSessionId = obj["sessionId"];

  const auto cmd = ParseCommandType(commandName);
  const mdbjson::JsonValue &args = obj["arguments"];
  switch (cmd) {
  case CommandType::Attach: {
    IfInvalidArgsReturn(Attach);
    return Attach::create(std::move(arg), args);
  }
  case CommandType::BreakpointLocations:
    TODO("Command::BreakpointLocations");
  case CommandType::Completions:
    TODO("Command::Completions");
  case CommandType::ConfigurationDone: {
    IfInvalidArgsReturn(ConfigurationDone);
    return new ConfigurationDone{ std::move(arg) };
  } break;
  case CommandType::Continue: {
    IfInvalidArgsReturn(Continue);

    bool all_threads = false;
    if (args.Contains("singleThread")) {
      const bool b = args["singleThread"];
      all_threads = !b;
    }

    return new Continue{ std::move(arg), args["threadId"], all_threads };
  }
  case CommandType::CustomRequest: {
    if (args.Contains("command") && args.Contains("arguments")) {
      std::string_view customCommand = args["command"];
      return ParseCustomRequestCommand(client, std::move(arg), customCommand, args["arguments"]);
    }
    return new InvalidArgs{ std::move(arg), "customRequest", {} };
  }
  case CommandType::DataBreakpointInfo:
    TODO("Command::DataBreakpointInfo");
  case CommandType::Disassemble: {
    IfInvalidArgsReturn(Disassemble);

    std::string_view addrString = args["memoryReference"];
    const auto addr = ToAddress(addrString);
    int offset = args["offset"];
    int instructionOffset = args["instructionOffset"];
    int instructionCount = args["instructionCount"];
    return new ui::dap::Disassemble{ std::move(arg), addr, offset, instructionOffset, instructionCount, false };
  }
  case CommandType::Disconnect: {
    IfInvalidArgsReturn(Disconnect);

    bool restart = false;
    bool terminateDebuggee = false;
    bool suspendDebuggee = false;
    if (args.Contains("restart")) {
      restart = args["restart"];
    }
    if (args.Contains("terminateDebuggee")) {
      terminateDebuggee = args["terminateDebuggee"];
    }
    if (args.Contains("suspendDebuggee")) {
      suspendDebuggee = args["suspendDebuggee"];
    }
    return new Disconnect{ std::move(arg), restart, terminateDebuggee, suspendDebuggee };
  }
  case CommandType::Evaluate: {
    return Evaluate::PrepareEvaluateCommand(std::move(arg), args);
  }
  case CommandType::ExceptionInfo:
    TODO("Command::ExceptionInfo");
  case CommandType::Goto:
    TODO("Command::Goto");
  case CommandType::GotoTargets:
    TODO("Command::GotoTargets");
  case CommandType::Initialize:
    IfInvalidArgsReturn(Initialize);
    return new Initialize{ std::move(arg), args };
  case CommandType::Launch: {
    IfInvalidArgsReturn(Launch);

    SessionId sessionId = args["sessionId"];
    Path path{ args["program"]->UncheckedGetStringView() };
    Path cwd;
    std::pmr::vector<std::pmr::string> prog_args{ arg.allocator->GetAllocator() };
    if (args.Contains("args")) {
      for (const auto &v : args.AsSpan("args")) {
        std::pmr::string arg;
        std::format_to(std::back_inserter(arg), "{}", v);
        prog_args.push_back(std::move(arg));
      }
    }

    bool stopOnEntry = false;
    if (args.Contains("stopOnEntry")) {
      stopOnEntry = args["stopOnEntry"];
    }

    if (args.Contains("env")) {
    }

    if (args.Contains("cwd")) {
    }

    const auto behaviorSetting = args.Get("breakpointBehavior")
                                   .and_then([](const auto &json) { return json.GetStringView(); })
                                   .transform([](const std::string_view &behavior) {
                                     if (behavior == "Stop all threads") {
                                       return BreakpointBehavior::StopAllThreadsWhenHit;
                                     } else if (behavior == "Stop single thread") {
                                       return BreakpointBehavior::StopOnlyThreadThatHit;
                                     } else {
                                       return BreakpointBehavior::StopAllThreadsWhenHit;
                                     }
                                   })
                                   .value_or(BreakpointBehavior::StopAllThreadsWhenHit);

    return new Launch{
      std::move(arg), sessionId, stopOnEntry, std::move(path), std::move(prog_args), behaviorSetting
    };
  }
  case CommandType::LoadedSources:
    TODO("Command::LoadedSources");
  case CommandType::Modules:
    TODO("Command::Modules");
  case CommandType::Next: {
    IfInvalidArgsReturn(Next);

    int threadId = args["threadId"];
    bool singleThread = false;
    SteppingGranularity stepType = SteppingGranularity::Line;
    if (args.Contains("granularity")) {
      std::string_view str_arg = args["granularity"];
      stepType = from_str(str_arg);
    }
    if (args.Contains("singleThread")) {
      singleThread = args["singleThread"];
    }
    return new Next{ std::move(arg), threadId, !singleThread, stepType };
  }
  case CommandType::Pause: {
    IfInvalidArgsReturn(Pause);
    int threadId = args["threadId"];
    return new Pause(std::move(arg), Pause::Args{ threadId });
  }
  case CommandType::ReadMemory: {
    IfInvalidArgsReturn(ReadMemory);

    std::string_view addrString = args["memoryReference"];
    const auto addr = ToAddress(addrString);

    const auto offset = args.Contains("offset") ? i32{ args["offset"] } : 0;
    const u64 count = args["count"];
    return new ui::dap::ReadMemory{ std::move(arg), addr, offset, count };
  }
  case CommandType::Restart:
    TODO("Command::Restart");
  case CommandType::RestartFrame:
    TODO("Command::RestartFrame");
  case CommandType::ReverseContinue: {
    IfInvalidArgsReturn(ReverseContinue);
    int threadId = args["threadId"];
    return new ui::dap::ReverseContinue{ std::move(arg), threadId };
  }
  case CommandType::Scopes: {
    IfInvalidArgsReturn(Scopes);

    const int frame_id = args["frameId"];
    return new ui::dap::Scopes{ std::move(arg), frame_id };
  }
  case CommandType::SetBreakpoints:
    IfInvalidArgsReturn(SetBreakpoints);

    return new SetBreakpoints{ std::move(arg), args };
  case CommandType::SetDataBreakpoints:
    TODO("Command::SetDataBreakpoints");
  case CommandType::SetExceptionBreakpoints: {
    IfInvalidArgsReturn(SetExceptionBreakpoints);
    return new SetExceptionBreakpoints{ std::move(arg), std::move(args) };
  }
  case CommandType::SetExpression:
    TODO("Command::SetExpression");
  case CommandType::SetFunctionBreakpoints:
    IfInvalidArgsReturn(SetFunctionBreakpoints);

    return new SetFunctionBreakpoints{ std::move(arg), std::move(args) };
  case CommandType::SetInstructionBreakpoints:
    IfInvalidArgsReturn(SetInstructionBreakpoints);

    return new SetInstructionBreakpoints{ std::move(arg), std::move(args) };
  case CommandType::SetVariable:
    TODO("Command::SetVariable");
  case CommandType::Source:
    TODO("Command::Source");
  case CommandType::StackTrace: {
    IfInvalidArgsReturn(StackTrace);

    std::optional<int> startFrame;
    std::optional<int> levels;
    std::optional<StackTraceFormat> format_;
    if (args.Contains("startFrame")) {
      startFrame = args["startFrame"];
    }
    if (args.Contains("levels")) {
      levels = args["levels"];
    }
    if (args.Contains("format")) {
      mdbjson::JsonValue fmt = args["format"];
      StackTraceFormat format;
      format.parameters = fmt.Value("parameters", true);
      format.parameterTypes = fmt.Value("parameterTypes", true);
      format.parameterNames = fmt.Value("parameterNames", true);
      format.parameterValues = fmt.Value("parameterValues", true);
      format.line = fmt.Value("line", true);
      format.module = fmt.Value("module", false);
      format.includeAll = fmt.Value("includeAll", true);
      format_ = format;
    }
    return new ui::dap::StackTrace{ std::move(arg), args["threadId"], startFrame, levels, format_ };
  }
  case CommandType::StepBack:
    TODO("Command::StepBack");
  case CommandType::StepIn: {
    IfInvalidArgsReturn(StepIn);

    int threadId = args["threadId"];
    bool singleThread = false;
    SteppingGranularity step_type = SteppingGranularity::Line;
    if (args.Contains("granularity")) {
      std::string_view str_arg = args["granularity"];
      step_type = from_str(str_arg);
    }
    if (args.Contains("singleThread")) {
      singleThread = args["singleThread"];
    }

    return new StepIn{ std::move(arg), threadId, singleThread, step_type };
  }
  case CommandType::StepInTargets:
    TODO("Command::StepInTargets");
  case CommandType::StepOut: {
    IfInvalidArgsReturn(StepOut);

    int threadId = args["threadId"];
    bool singleThread = false;
    if (args.Contains("singleThread")) {
      singleThread = args["singleThread"];
    }
    return new ui::dap::StepOut{ std::move(arg), threadId, !singleThread };
  }
  case CommandType::Terminate:
    IfInvalidArgsReturn(Terminate);

    return new Terminate{ std::move(arg) };
  case CommandType::TerminateThreads:
    TODO("Command::TerminateThreads");
  case CommandType::Threads:
    IfInvalidArgsReturn(Threads);

    return new Threads{ std::move(arg) };
  case CommandType::Variables: {
    IfInvalidArgsReturn(Variables);

    VariableReferenceId variablesReference = args["variablesReference"];
    std::optional<u32> start{};
    std::optional<u32> count{};
    if (args.Contains("start")) {
      start = args["start"];
    }
    if (args.Contains("count")) {
      count = args["count"];
    }
    return new Variables{ std::move(arg), variablesReference, start, count };
  }
  case CommandType::WriteMemory: {
    IfInvalidArgsReturn(WriteMemory);
    std::string_view addrString = args["memoryReference"];
    const auto addr = ToAddress(addrString);
    int offset = 0;
    if (args.Contains("offset")) {
      offset = args["offset"];
    }

    std::string_view data = args["data"];

    if (auto bytes = mdb::decode_base64(data); bytes) {
      return new WriteMemory{ std::move(arg), addr, offset, std::move(bytes.value()) };
    } else {
      return new InvalidArgs{ std::move(arg), "writeMemory", {} };
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