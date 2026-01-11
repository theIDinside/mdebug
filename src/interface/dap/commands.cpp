/** LICENSE TEMPLATE */

#include "commands.h"

// mdb
#include <bp.h>
#include <common.h>
#include <common/formatter.h>
#include <event_queue.h>
#include <events/event.h>
#include <interface/attach_args.h>
#include <interface/dap/custom_commands.h>
#include <interface/dap/dap_defs.h>
#include <interface/dap/events.h>
#include <interface/dap/interface.h>
#include <interface/dap/parse_buffer.h>
#include <interface/tracee_command/ptrace/ptrace_session.h>
#include <interface/tracee_command/rr/rr_session.h>
#include <interface/tracee_command/rr/rr_supervisor.h>
#include <interface/tracee_command/supervisor_state.h>
#include <interface/ui_command.h>
#include <symbolication/callstack.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <task.h>
#include <task_scheduling.h>
#include <tracer.h>
#include <utils/base64.h>
#include <utils/format_utils.h>
#include <utils/logger.h>
#include <utils/todo.h>
#include <utils/util.h>

// system

// std
#include <algorithm>
#include <filesystem>
#include <iterator>
#include <optional>
#include <string>

template <typename T> using Set = std::unordered_set<T>;

namespace ui = mdb::ui;
template <> struct std::formatter<ui::dap::Message>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const ui::dap::Message &msg, FormatContext &ctx) const
  {

    if (msg.Variables().empty()) {
      return std::format_to(ctx.out(),
        R"({{"id":{},"format":"{}","showUser":{}}})",
        msg.MessageId().value_or(-1),
        msg.Format(),
        msg.ShowToUser());
    } else {
      auto sz = 1u;
      auto max = msg.Variables().size();
      auto it = std::format_to(
        ctx.out(), R"({{ "id": {}, "format": "{}","variables":{{)", msg.MessageId().value_or(-1), msg.Format());
      for (const auto &[k, v] : msg.Variables()) {
        if (sz < max) {
          it = std::format_to(it, R"("{}":"{}", )", k, v);
        } else {
          it = std::format_to(it, R"("{}":"{}")", k, v);
        }
        ++sz;
      }

      return std::format_to(it, R"(}}, "showUser":{}}})", msg.ShowToUser());
    }
  }
};

#define GetSessionOrSendError()                                                                                   \
  ({                                                                                                              \
    auto supervisor = GetSupervisor();                                                                            \
    if (!supervisor) {                                                                                            \
      std::pmr::string err{ MemoryResource() };                                                                   \
      std::format_to(std::back_inserter(err), "Session '{}' could not be found.", mProcessId);                    \
      WriteResponse(ErrorResponse{ Request, this, std::move(err), {} });                                          \
      return;                                                                                                     \
    }                                                                                                             \
    supervisor;                                                                                                   \
  })

#define GetSupervisoOrSendError()                                                                                 \
  ({                                                                                                              \
    auto supervisor = GetSessionOrSendError();                                                                    \
    if (supervisor->IsExited()) {                                                                                 \
      DBGBUFLOG(core, "Could not find supervisor for session {} ({})", mProcessId, __PRETTY_FUNCTION__);          \
      std::pmr::string err{ MemoryResource() };                                                                   \
      std::format_to(std::back_inserter(err), "Could not find supervisor for session {}", mProcessId);            \
      WriteResponse(ErrorResponse{ Request, this, std::move(err), {} });                                          \
      return;                                                                                                     \
    }                                                                                                             \
    supervisor;                                                                                                   \
  })

namespace mdb {

namespace ui {

void
UICommand::WriteResponse(const UIResult &result) noexcept
{
  auto data = result.Serialize(0);
  if (!data.empty()) {
    mDebugAdapterManager->WriteSerializedProtocolMessage(data);
  }
}

tc::SupervisorState *
UICommand::GetSupervisor() noexcept
{
  return mDebugAdapterManager->GetSupervisor(mProcessId);
}
} // namespace ui

namespace ui::dap {

static constexpr auto kSessionTypePtrace = "ptrace"sv;
static constexpr auto kSessionTypeRr = "rr"sv;
static constexpr auto kSessionTypeGdbRemote = "gdbremote"sv;

Message::Message(std::string_view message, std::pmr::memory_resource *rsrc) noexcept
    : mFormat(rsrc), mVariables(rsrc)
{
  CopyTo(message, mFormat);
}

Message::Message(std::pmr::string message, std::pmr::memory_resource *rsrc) noexcept
    : mFormat(std::move(message)), mVariables(rsrc)
{
}

template <typename Res>
inline std::optional<Res>
get(const mdbjson::JsonValue &obj, std::string_view field)
{
  if (obj.Contains(field)) {
    Res result = obj[field];
    return std::make_optional(std::move(result));
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
    std::optional<std::pmr::string> &&shortMessage,
    std::optional<Message> &&message) noexcept
      : ui::UIResult(false, cmd), mPid(cmd->mProcessId), mCommand(command), mShortMessage(std::move(shortMessage)),
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","message":"{}","body":{{"error":{}}}}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand,
        *mShortMessage,
        m);
    } else if (mShortMessage && !mMessage) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","message":"{}"}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand,
        *mShortMessage);
    } else if (!mShortMessage && mMessage) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}","body":{{"error":{}}}}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand,
        *mMessage);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"{}"}})",
        seq,
        mRequestSeq,
        mPid,
        mCommand);
    }
    return result;
  }

  SessionId mPid;
  std::string_view mCommand;
  std::optional<std::pmr::string> mShortMessage;
  std::optional<Message> mMessage;
};

struct PauseResponse final : public ui::UIResult
{
  ~PauseResponse() noexcept override = default;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"pause"}})",
        seq,
        mRequestSeq,
        mProcessId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"pause","message":"taskwasnotrunning"}})",
        seq,
        mRequestSeq,
        mProcessId);
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

  void
  Execute() noexcept final
  {
    auto target = GetSupervisoOrSendError();

    MDB_ASSERT(target, "No target {}", mProcessId);
    bool success = target->Pause(mPauseArgs.mThreadId);
    WriteResponse(PauseResponse{ success, this });
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"reverseContinue","body":{{"allThreadsContinued":true}}}})",
        seq,
        mRequestSeq,
        mProcessId,
        mContinueAll);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"reverseContinue","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mProcessId);
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

  void
  Execute() noexcept final
  {
    auto supervisor = GetSupervisor();
    // TODO: This is the only command where it's ok to get a nullptr for target, in that case, we should just pick
    // _any_ target, and use that to resume backwards (since RR is the controller.).
    MDB_ASSERT(supervisor, "must have target.");
    auto ok = supervisor->ReverseResumeTarget(tc::RunType::Continue);
    WriteResponse(ReverseContinueResponse{ ok, this });
  }

  DEFINE_NAME("reverseContinue");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct ContinueResponse final : ui::UIResult
{
  ContinueResponse(bool success, bool continueAll, UICommandPtr cmd) noexcept
      : UIResult(success, cmd), mContinueAll(continueAll)
  {
  }

  ~ContinueResponse() noexcept override = default;
  bool mContinueAll;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    auto outIt = std::back_inserter(result);
    if (mSuccess) {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"continue","body":{{"allThreadsContinued":{}}}}})",
        seq,
        mRequestSeq,
        mProcessId,
        mContinueAll);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"continue","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mProcessId);
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

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();

    bool success = false;
    DBGLOG(control, "user requested resume, all={}, thread={}", mContinueAll, mThreadId);

    if (mContinueAll || !target->SingleThreadControl()) {
      target->ResumeTarget(tc::RunType::Continue);
      success = true;
    } else {
      auto task = target->GetTaskByTid(mThreadId);
      if (task && task->CanContinue()) {
        target->ResumeTask(*task, tc::RunType::Continue);
        success = true;
      } else {
        DBGBUFLOG(core, "task {} could not be resumed", mThreadId);
        success = false;
      }
    }

    WriteResponse(ContinueResponse{ success, mContinueAll, this });
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"next"}})",
        seq,
        mRequestSeq,
        mProcessId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"next","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mProcessId);
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

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();

    auto task = target->GetTaskByTid(mThreadId);

    if (!task) {
      DBGLOG(core, "No task with id {} found", mThreadId);
      return WriteResponse(NextResponse{ false, this });
    }

    if (!task->IsStopped()) {
      DBGLOG(core, "task {} is not stopped", task->mTid);
      return WriteResponse(NextResponse{ false, this });
    }

    bool success = false;
    switch (granularity) {
    case SteppingGranularity::Instruction:
      success =
        target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::InstructionStep>(*target, *task, 1));
      break;
    case SteppingGranularity::Line:
      success = target->SetAndCallRunAction(task->mTid, ptracestop::LineStep::FallibleMake(*target, *task));
      break;
    case SteppingGranularity::LogicalBreakpointLocation:
      TODO("Next::execute granularity=SteppingGranularity::LogicalBreakpointLocation")
      break;
    }
    return WriteResponse(NextResponse{ success, this });
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stepBack"}})",
        seq,
        mRequestSeq,
        mProcessId);
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"stepBack","message":"{}"}})",
        seq,
        mRequestSeq,
        mProcessId,
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

  void
  Execute() noexcept final
  {
    TODO("Implement StepBack again");
    // auto target = GetSupervisor();
    // MDB_ASSERT(target, "must have target");

    // if (!target->IsReplaySession()) {
    //   return WriteResponse(StepBackResponse{ StepBackResponse::Result::NotReplaySession, this });
    // } else if (target->IsRunning()) {
    //   // During reverse execution, because we are RR-oriented, the entire process will be stopped, so we don't
    //   have
    //   // to actually check individual tasks here.
    //   return WriteResponse(StepBackResponse{ StepBackResponse::Result::NotStopped, this });
    // }

    // target->ReverseResumeTarget(tc::RunType::Step);
    // return WriteResponse(StepBackResponse{ StepBackResponse::Result::Success, this });
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stepIn"}})",
        seq,
        mRequestSeq,
        mProcessId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"stepIn","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mProcessId);
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

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();

    auto task = target->GetTaskByTid(mThreadId);

    if (!task->IsStopped()) {
      return WriteResponse(StepInResponse{ false, this });
    }

    auto proceeder = ptracestop::StepInto::Create(*target, *task);

    if (!proceeder) {
      return WriteResponse(ErrorResponse{ Request,
        this,
        std::make_optional("No line table information could be found - abstract stepping not possible."),
        std::nullopt });
    }

    const bool success = target->SetAndCallRunAction(task->mTid, std::move(proceeder));
    return WriteResponse(StepInResponse{ success, this });
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stepOut"}})",
        seq,
        mRequestSeq,
        mProcessId);
    } else {
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"stepOut","message":"notStopped"}})",
        seq,
        mRequestSeq,
        mProcessId);
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

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();
    auto task = target->GetTaskByTid(thread_id);

    if (!task->IsStopped()) {
      return WriteResponse(StepOutResponse{ false, this });
    }
    const auto req = CallStackRequest::partial(2);
    auto resume_addrs = task->UnwindReturnAddresses(req);
    MDB_ASSERT(resume_addrs.size() >= static_cast<std::size_t>(req.count), "Could not find frame info");
    const auto rip = resume_addrs[1];
    auto loc = target->GetOrCreateBreakpointLocation(rip);
    if (!loc.is_expected()) {
      return WriteResponse(StepOutResponse{ false, this });
    }
    auto user = target->GetUserBreakpoints().CreateBreakpointLocationUser<FinishBreakpoint>(
      *target, std::move(loc), task->mTid, task->mTid);
    bool success =
      target->SetAndCallRunAction(task->mTid, std::make_shared<ptracestop::FinishFunction>(*target, *task, user));
    return WriteResponse(StepOutResponse{ success, this });
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
      : ui::UIResult(success, cmd), mType(type), mBreakpoints(this->mAllocator->GetAllocator())
  {
  }

  SetBreakpointsResponse(bool success,
    ui::UICommandPtr cmd,
    BreakpointRequestKind type,
    std::pmr::vector<ui::dap::Breakpoint> breakpoints) noexcept
      : ui::UIResult(success, cmd), mType(type), mBreakpoints(std::move(breakpoints))
  {
  }

  ~SetBreakpointsResponse() noexcept override = default;

  std::pmr::vector<ui::dap::Breakpoint> mBreakpoints;
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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"setBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mProcessId,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    case BreakpointRequestKind::function:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"setFunctionBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mProcessId,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    case BreakpointRequestKind::instruction:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"setInstructionBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mProcessId,
        JoinFormatIterator{ serializedBreakpoints, "," });
      break;
    case BreakpointRequestKind::exception:
      std::format_to(outIt,
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":{},"command":"setExceptionBreakpoints","body":{{"breakpoints":[{}]}}}})",
        seq,
        mRequestSeq,
        mProcessId,
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
private:
  inline void
  ExecuteDuringConfigPhase(Path file, Set<BreakpointSpecification> specs) noexcept
  {
    mDebugAdapterManager->OnSessionConfiguredWithSupervisor(
      [sessionId = mProcessId, dap = mDebugAdapterManager, file = std::move(file), specs = std::move(specs)](
        tc::SupervisorState &target) {
        // Set the breakpoints
        DBGBUFLOG(core, "Setting post poned source breakpoints");
        target.SetSourceBreakpoints(file, specs);
        // Then emit "new breakpoint" events, since we're not actually responding to a request, anymore.
        for (const auto &[bp, ids] : target.GetUserBreakpoints().GetBreakpointsFromSourceFile(file)) {
          for (const auto id : ids) {
            const auto user = target.GetUserBreakpoints().GetUserBreakpoint(id);
            dap->PostDapEvent(new ui::dap::BreakpointEvent{ sessionId, "new", {}, user });
          }
        }
      });
  }

public:
  SetBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept
      : ui::UICommand(std::move(arg)), args(arguments)
  {
    MDB_ASSERT(args.Contains("breakpoints") && args.UncheckedGetProperty("breakpoints")->IsArray(),
      "Arguments did not contain 'breakpoints' field or wasn't an array");
  }

  ~SetBreakpoints() override = default;

  mdbjson::JsonValue args;

  void
  Execute() noexcept final
  {
    auto target = GetSupervisor();

    MDB_ASSERT(args.Contains("source"), "setBreakpoints request requires a 'source' field");
    MDB_ASSERT(args.At("source")->Contains("path"), "source field requires a 'path' field");
    std::string_view file =
      args.UncheckedGetProperty("source")->UncheckedGetProperty("path")->UncheckedGetStringView();

    Set<BreakpointSpecification> specs;

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

      specs.insert(BreakpointSpecification::Create<SourceBreakpointSpecPair>(std::move(condition),
        std::move(hitCondition),
        std::string{ file },
        SourceBreakpointSpec{ .line = line, .column = column, .log_message = std::move(logMessage) }));
    }

    // If target == nullptr, means this is in the configuration phase of a session, because attach or launch has
    // not yet happened so we don't actually have a process and executable to set these for. In that event
    // respond with breakpoints: [], and then instead emit "new breakpoint" events for when the configuration phase
    // + attach/launch has happened.
    if (!target) {
      DBGBUFLOG(core, "Session {} has no supervisor yet, postponing breakpoint creation.", mProcessId);
      ExecuteDuringConfigPhase(Path{ file }, std::move(specs));
      return WriteResponse(SetBreakpointsResponse{ true, this, BreakpointRequestKind::source, {} });
    } else {
      target->SetSourceBreakpoints(file, specs);

      using BP = ui::dap::Breakpoint;

      auto breakpoints = Allocate<std::pmr::vector<ui::dap::Breakpoint>>();
      for (const auto &[bp, ids] : target->GetUserBreakpoints().GetBreakpointsFromSourceFile(file)) {
        for (const auto id : ids) {
          const auto user = target->GetUserBreakpoints().GetUserBreakpoint(id);
          breakpoints->push_back(BP::CreateFromUserBreakpoint(*user, MemoryResource()));
        }
      }

      WriteResponse(SetBreakpointsResponse{ true, this, BreakpointRequestKind::source, std::move(*breakpoints) });
    }
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

  void
  Execute() noexcept final
  {
    DBGLOG(core, "exception breakpoints not yet implemented");
    WriteResponse(SetBreakpointsResponse{ true, this, BreakpointRequestKind::exception });
  }

  mdbjson::JsonValue mArgs;

  DEFINE_NAME("setExceptionBreakpoints");
  RequiredArguments({ "filters"sv });
  DefineArgTypes({ "filters", FieldType::Array });
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
private:
  inline void
  ExecuteDuringConfigPhase(Set<BreakpointSpecification> specs) noexcept
  {
    mDebugAdapterManager->OnSessionConfiguredWithSupervisor(
      [sessionId = mProcessId, dap = mDebugAdapterManager, specs = std::move(specs)](tc::SupervisorState &target) {
        DBGBUFLOG(core, "Setting post poned instruction breakpoints");
        // Set the breakpoints
        target.SetInstructionBreakpoints(specs);
        // Then emit "new breakpoint" events, since we're not actually responding to a request, anymore.
        auto &userBreakpoints = target.GetUserBreakpoints();

        for (const auto &[k, id] : userBreakpoints.mInstructionBreakpoints) {
          dap->PostDapEvent(
            new ui::dap::BreakpointEvent{ sessionId, "new", {}, userBreakpoints.GetUserBreakpoint(id) });
        }
      });
  }

public:
  SetInstructionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept
      : UICommand{ std::move(arg) }, mArgs(arguments)
  {
    MDB_ASSERT(mArgs.Contains("breakpoints") && mArgs.At("breakpoints")->IsArray(),
      "Arguments did not contain 'breakpoints' field or wasn't an array");
  }

  ~SetInstructionBreakpoints() override = default;
  mdbjson::JsonValue mArgs;

  void
  Execute() noexcept final
  {
    auto target = GetSupervisor();

    using BP = ui::dap::Breakpoint;
    Set<BreakpointSpecification> specs{};
    const auto ibps = mArgs.AsSpan("breakpoints");
    auto breakpoints = Allocate<std::pmr::vector<ui::dap::Breakpoint>>();
    for (const auto &insBreakpoint : ibps) {
      MDB_ASSERT(
        insBreakpoint.Contains("instructionReference") && insBreakpoint.At("instructionReference")->IsString(),
        "instructionReference field not in args or wasn't of type string");
      std::string_view addrString = insBreakpoint["instructionReference"];
      specs.insert(BreakpointSpecification::Create<InstructionBreakpointSpec>({}, {}, std::string{ addrString }));
    }

    if (!target) {
      ExecuteDuringConfigPhase(std::move(specs));
      return WriteResponse(SetBreakpointsResponse{ true, this, BreakpointRequestKind::instruction, {} });
    } else {
      target->SetInstructionBreakpoints(specs);

      auto &userBreakpoints = target->GetUserBreakpoints();
      breakpoints->reserve(userBreakpoints.mInstructionBreakpoints.size());

      for (const auto &[k, id] : userBreakpoints.mInstructionBreakpoints) {
        breakpoints->push_back(
          BP::CreateFromUserBreakpoint(*userBreakpoints.GetUserBreakpoint(id), MemoryResource()));
      }

      WriteResponse(
        SetBreakpointsResponse{ true, this, BreakpointRequestKind::instruction, std::move(*breakpoints) });
    }
  }
  DEFINE_NAME("setInstructionBreakpoints");
  RequiredArguments({ "breakpoints"sv });
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
private:
  inline void
  ExecuteDuringConfigPhase(Set<BreakpointSpecification> specs) noexcept
  {
    mDebugAdapterManager->OnSessionConfiguredWithSupervisor(
      [sessionId = mProcessId, dap = mDebugAdapterManager, specs = std::move(specs)](tc::SupervisorState &target) {
        DBGBUFLOG(core, "Setting post poned function breakpoints");
        // Set the breakpoints
        target.SetFunctionBreakpoints(specs);
        // Then emit "new breakpoint" events, since we're not actually responding to a request, anymore.
        for (const auto &user : target.GetUserBreakpoints().AllUserBreakpoints()) {
          if (user->mKind == LocationUserKind::Function) {
            dap->PostDapEvent(new ui::dap::BreakpointEvent{ sessionId, "new", {}, user });
          }
        }
      });
  }

public:
  SetFunctionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept
      : UICommand{ std::move(arg) }, mArgs(arguments)
  {
    MDB_ASSERT(mArgs.Contains("breakpoints") && mArgs.At("breakpoints")->IsArray(),
      "Arguments did not contain 'breakpoints' field or wasn't an array");
  }

  ~SetFunctionBreakpoints() override = default;

  mdbjson::JsonValue mArgs;

  void
  Execute() noexcept final
  {
    auto target = GetSupervisor();

    using BP = ui::dap::Breakpoint;
    Set<BreakpointSpecification> specs{};
    auto breakpoints = Allocate<std::pmr::vector<ui::dap::Breakpoint>>();

    for (const auto &fnbkpt : mArgs.AsSpan("breakpoints")) {
      MDB_ASSERT(fnbkpt.Contains("name") && fnbkpt["name"]->IsString(),
        "instructionReference field not in args or wasn't of type string");
      std::string functionName = fnbkpt["name"];
      bool isRegex = false;
      if (fnbkpt.Contains("regex")) {
        isRegex = fnbkpt["regex"];
      }

      specs.insert(
        BreakpointSpecification::Create<FunctionBreakpointSpec>({}, {}, std::move(functionName), isRegex));
    }

    if (!target) {
      ExecuteDuringConfigPhase(std::move(specs));
      WriteResponse(SetBreakpointsResponse{ true, this, BreakpointRequestKind::function, {} });
    } else {
      target->SetFunctionBreakpoints(specs);
      for (const auto &user : target->GetUserBreakpoints().AllUserBreakpoints()) {
        if (user->mKind == LocationUserKind::Function) {
          breakpoints->push_back(BP::CreateFromUserBreakpoint(*user, MemoryResource()));
        }
      }

      WriteResponse(
        SetBreakpointsResponse{ true, this, BreakpointRequestKind::function, std::move(*breakpoints) });
    }
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":{},"command":"writeMemory","body":{{"bytesWritten":{}}}}})",
      seq,
      mRequestSeq,
      mProcessId,
      mSuccess,
      bytes_written);
    return result;
  }
  u64 bytes_written;
};

struct WriteMemory final : public ui::UICommand
{
  WriteMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset, std::pmr::vector<u8> &&bytes) noexcept
      : ui::UICommand(std::move(arg)), mAddress(address), mOffset(offset), mBytes(std::move(bytes))
  {
  }

  ~WriteMemory() override = default;

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();
    PROFILE_SCOPE_ARGS("WriteMemory", "command", PEARG("seq", mSeq));
    auto response = mCommandAllocator->Allocate<WriteMemoryResponse>(false, this);
    response->bytes_written = 0;
    if (mAddress) {
      const auto result = target->DoWriteBytes(mAddress.value(), mBytes.data(), mBytes.size());
      response->mSuccess = result.mWasSuccessful;
      if (result.mWasSuccessful) {
        response->bytes_written = result.uBytesWritten;
      }
    }

    return WriteResponse(*response);
  }

  std::optional<AddrPtr> mAddress;
  int mOffset;
  std::pmr::vector<u8> mBytes;

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
        R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"readMemory","body":{{"address":"{}","unreadableBytes":{},"data":"{}"}}}})",
        seq,
        mRequestSeq,
        mProcessId,
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

  void
  Execute() noexcept final
  {
    if (mAddress) {
      PROFILE_SCOPE_ARGS(
        "ReadMemory", "command", PEARG("seq", mSeq), PEARG("addr", *mAddress), PEARG("bytes", mBytes));
      auto *target = GetSupervisoOrSendError();
      auto sv = target->ReadToVector(*mAddress, mBytes, MemoryResource());
      auto res = mCommandAllocator->Allocate<ReadMemoryResponse>(true, this);

      // TODO: Make pointer to memory resource shared? Easier to not get wrong. As soon as the response object is
      // created, the allocator is moved into the response object.
      res->mBase64Data = mdb::EncodeIntoBase64(sv->span(), res->MemoryResource());
      res->mFirstReadableAddress = *mAddress;
      res->mSuccess = true;
      res->mUnreadableBytes = 0;
      return WriteResponse(*res);
    } else {
      return WriteResponse(ErrorResponse{ Request,
        this,
        std::pmr::string{ "Address parameter could not be parsed.", MemoryResource() },
        std::nullopt });
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
  ConfigurationDoneResponse(bool postponed, bool success, UICommandPtr cmd) noexcept
      : UIResult(success, cmd), mPostPoned(postponed) {};
  ~ConfigurationDoneResponse() noexcept override = default;

  bool mPostPoned;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);

    std::format_to(std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"configurationDone", "body":{{"postponed":{}}}}})",
      seq,
      mRequestSeq,
      mProcessId,
      mPostPoned);
    return result;
  }
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}

  ~ConfigurationDone() override = default;

  void
  Execute() noexcept final
  {
    bool postponed = false;
    if (auto target = GetSupervisor(); target) {
      bool success = target->ConfigurationDone();
      postponed = false;
    } else {
      DBGLOG(core, "No target to run configuration done on");
      postponed = true;
      mDebugAdapterManager->ConfigDoneWithNoSupervisor();
    }
    return WriteResponse(ConfigurationDoneResponse{ postponed, /*success*/ true, /*cmd*/ this });
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"disconnect"}})",
      seq,
      mRequestSeq,
      mProcessId);
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

  void
  Execute() noexcept final
  {
    // We don't allow for child sessions to be terminated, and not have the entire application torn down.
    // We only allow for suspension, or detaching individual child sessions. This behavior is also mimicked for RR
    // sessions, as destroying a process would invalidate the entire application trace.
    auto target = GetSessionOrSendError();

    if (!target || target->IsExited()) {
      WriteResponse(DisconnectResponse{ true, this });
    } else {
      target->Disconnect(mTerminateTracee);
      mDebugAdapterManager->PushDelayedEvent(new DisconnectResponse{ true, this });
    }
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

  void
  Execute() noexcept final
  {
    DBGLOG(core, "Executing initialize request, session id={}", mProcessId);
    bool RRSession = false;
    if (mArgs.Contains("RRSession") && mArgs["RRSession"]->IsBoolean()) {
      RRSession = mArgs["RRSession"];
    }

    mDebugAdapterManager->PushDelayedEvent(new ui::dap::InitializedEvent{ mProcessId, {} });
    return WriteResponse(InitializeResponse{ RRSession, true, this });
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
    R"({{"seq":0,"request_seq":{},"processId":0,"type":"response","success":true,"command":"initialize","body": {} }})",
    mRequestSeq,
    body);
  return res;
}

struct LaunchResponse final : public UIResult
{
  LaunchResponse(std::optional<Pid> newProcess, bool success, UICommandPtr cmd) noexcept
      : UIResult{ success, cmd }, mDeterminedProcessId{ newProcess }
  {
  }
  ~LaunchResponse() noexcept override = default;

  std::optional<Pid> mDeterminedProcessId;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    VERIFY(mDeterminedProcessId.has_value(), "Failed to launch binary, but not responding with ErrorResponse?");

    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"launch", "body": {{ "processId": {} }}}})",
      seq,
      mRequestSeq,
      mProcessId,
      *mDeterminedProcessId);
    return result;
  }
};

struct RRLaunchResponse final : public UIResult
{
  RRLaunchResponse(Pid firstProcess, std::vector<Pid> processes, bool success, UICommandPtr cmd) noexcept
      : UIResult{ success, cmd }, mFirstProcess(firstProcess), mProcesses(std::move(processes))
  {
  }

  ~RRLaunchResponse() noexcept override = default;

  Pid mFirstProcess;
  std::vector<Pid> mProcesses;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);

    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"launch", "body": {{ "processId": {}, "processes": [{}] }}}})",
      seq,
      mRequestSeq,
      mProcessId,
      mFirstProcess,
      JoinFormatIterator{ mProcesses });
    return result;
  }
};

struct Launch : public UICommand
{
  static constexpr auto kPtraceSession = "ptrace"sv;
  static constexpr auto kReplaySession = "rr"sv;

  Launch(UICommandArg arg, bool stopOnEntry, std::optional<BreakpointBehavior> breakpointBehavior) noexcept
      : UICommand{ std::move(arg) }, mStopOnEntry(stopOnEntry), mBreakpointBehavior(breakpointBehavior)
  {
  }
  ~Launch() noexcept override = default;

  static RefPtr<ui::UICommand> CreateRequest(UICommandArg arg, const mdbjson::JsonValue &args) noexcept;

  bool mStopOnEntry;
  std::optional<BreakpointBehavior> mBreakpointBehavior;

  DEFINE_NAME("launch"sv);
  RequiredArguments({ "type"sv });
  DefineArgTypes({ "type"sv, FieldType::Enumeration, { kPtraceSession, kReplaySession } });
};

struct NativeLaunch final : public Launch
{
  // Native launch
  NativeLaunch(UICommandArg arg,
    bool stopOnEntry,
    std::optional<BreakpointBehavior> breakpointBehavior,
    std::string_view program,
    std::pmr::vector<std::pmr::string> programArgs,
    std::pmr::vector<std::pmr::string> environVars,
    std::pmr::string currentWorkingDir) noexcept
      : Launch{ std::move(arg), stopOnEntry, breakpointBehavior, }, mProgram{ program },
        mCurrentWorkingDir{ std::move(currentWorkingDir) }, mEnvironmenVariables{ std::move(environVars) },
        mProgramArgs{ std::move(programArgs) }
  {
  }

  ~NativeLaunch() noexcept final = default;

  static RefPtr<ui::UICommand> CreateRequest(UICommandArg arg,
    bool stopOnEntry,
    std::optional<BreakpointBehavior> behaviorSetting,
    const mdbjson::JsonValue &args) noexcept;

  void
  Execute() noexcept final
  {
    PROFILE_SCOPE_ARGS(
      "launch", "command", PEARG("program", mProgram), PEARG("progArgs", std::span{ mProgramArgs }));

    auto process = tc::ptrace::Session::ForkExec(
      mDebugAdapterManager, mStopOnEntry, mProgram, mProgramArgs, mBreakpointBehavior);

    DBGLOG(core, "Responding to launch request, resuming target {}", process->TaskLeaderTid());

    // Queue a pseudo stop event that will force a start during configurationDone by processing deferred events.
    process->QueuePending(StopStatus{ .ws = StopKind::Stopped, .mPid = process->TaskLeaderTid() });
    WriteResponse(LaunchResponse{ process->TaskLeaderTid(), true, this });

    const bool configPhaseDone = mDebugAdapterManager->SupervisorMaterialized({ process });
    DBGLOG(core, "Configuration phase executed with materialized supervisor: {}", configPhaseDone);
    if (mDebugAdapterManager->HasPendingConfigDone()) {
      process->ProcessDeferredEvents();
      process->ProcessQueuedUnhandled(process->TaskLeaderTid());
      mDebugAdapterManager->ConfigDoneWithNoSupervisor(false);
    } else {
      process->OnConfigurationDone([&](mdb::tc::SupervisorState *supervisor) {
        mdb::tc::ptrace::Session *process = static_cast<mdb::tc::ptrace::Session *>(supervisor);
        process->ProcessDeferredEvents();
        process->ProcessQueuedUnhandled(process->TaskLeaderTid());
        return true;
      });
    }
  }

  std::string_view mProgram;
  std::pmr::string mCurrentWorkingDir;
  std::pmr::vector<std::pmr::string> mEnvironmenVariables;
  std::pmr::vector<std::pmr::string> mProgramArgs;

  RequiredArguments({ "program"sv });
  DefineArgTypes({ "program", FieldType::String });
};

/* static */
RefPtr<ui::UICommand>
NativeLaunch::CreateRequest(UICommandArg arg,
  bool stopOnEntry,
  std::optional<BreakpointBehavior> behaviorSetting,
  const mdbjson::JsonValue &args) noexcept
{
  IfInvalidArgsReturn(NativeLaunch);

  std::string_view program = args["program"]->UncheckedGetStringView();
  std::pmr::vector<std::pmr::string> programArguments{ arg.allocator->GetAllocator() };
  if (args.Contains("args")) {
    for (const auto &v : args.AsSpan("args")) {
      std::pmr::string arg;
      std::format_to(std::back_inserter(arg), "{}", v);
      programArguments.push_back(std::move(arg));
    }
  }

  std::pmr::vector<std::pmr::string> environVars{ arg.allocator->GetAllocator() };

  if (args.Contains("env") && args["env"]->IsArray()) {
    const auto env = args["env"]->AsSpan();
    environVars.reserve(env.size());
    for (const auto &jsonValue : env) {
      if (jsonValue.IsString()) {
        environVars.push_back(*jsonValue.GetString());
      }
    }
  }

  std::pmr::string currentWorkingDir{ arg.allocator->GetAllocator() };

  if (args.Contains("cwd") && args["cwd"]->IsString()) {
    currentWorkingDir = *args["cwd"]->GetString();
  }

  return RefPtr<NativeLaunch>::MakeShared(std::move(arg),
    stopOnEntry,
    behaviorSetting,
    program,
    std::move(programArguments),
    std::move(environVars),
    std::move(currentWorkingDir));
}

struct RRLaunch final : public Launch
{
  RRLaunch(UICommandArg arg,
    bool stopOnEntry,
    std::optional<BreakpointBehavior> breakpointBehavior,
    std::string_view traceDir) noexcept
      : Launch{ std::move(arg), stopOnEntry, breakpointBehavior }, mTraceDirectory(traceDir)
  {
  }

  ~RRLaunch() noexcept final = default;

  std::string_view mTraceDirectory;

  RequiredArguments({ "traceDir"sv });
  DefineArgTypes({ "traceDir", FieldType::String });

  void
  OnReplayStarted(tc::replay::ReplaySupervisor *replaySupervisor) noexcept
  {
    namespace replay = tc::replay;

    // TODO: Add the ability to "go to" event N and start from there. But regardless if that feature gets
    // implemented keep StartReplay as the method to go to event 15, as this is post rr_exec_stub being executed;
    // and after this point, we can interrupt a go-to-event-N (if user wants to), by having the user interrupt
    // it. But the user can not interrupt pre event 15.

    auto processes = replaySupervisor->CurrentLiveProcesses();
    MDB_ASSERT(!processes.empty(), "No live processes?");
    const bool hasReplayedStep = true;
    replay::Session *session =
      replay::Session::Create(replaySupervisor, processes.front(), mDebugAdapterManager, hasReplayedStep);

    const bool configPhaseDone = mDebugAdapterManager->SupervisorMaterialized({ session });
    WriteResponse(RRLaunchResponse{
      replaySupervisor->CurrentLiveProcesses().front(), replaySupervisor->CurrentLiveProcesses(), true, this });
    session->PostExec(replaySupervisor->ExecedFile(session->TaskLeaderTid()), true, true);

    if (mDebugAdapterManager->HasPendingConfigDone() || session->IsConfigured()) {
      session->EmitStopped(session->TaskLeaderTid(), ui::dap::StoppedReason::Entry, "attached", true, {});
      mDebugAdapterManager->ConfigDoneWithNoSupervisor(false);
    } else {
      session->OnConfigurationDone([processes = std::move(processes)](tc::SupervisorState *supervisor) {
        DBGBUFLOG(core, "Configuration done; request attaching of additional processes if necessary.");
        auto *session = static_cast<replay::Session *>(supervisor);
        replay::ReplaySupervisor *replaySupervisor = session->GetReplaySupervisor();
        session->EmitStopped(session->TaskLeaderTid(), ui::dap::StoppedReason::Entry, "attached", true, {});
        return true;
      });
    }
  }

  void
  Execute() noexcept final
  {
    PROFILE_SCOPE_ARGS("launch", "command", PEARG("traceDir", mTraceDirectory));

    namespace replay = mdb::tc::replay;
    DBGBUFLOG(core, "[launch]: Creating replay supervisor");
    auto replaySupervisor = replay::ReplaySupervisor::Create(tc::replay::RRInitOptions{});

    replaySupervisor->StartReplay(mTraceDirectory.data(),
      [cmd = RefPtr{ this }, replaySupervisor]() -> void { cmd->OnReplayStarted(replaySupervisor); });
  }

  static RefPtr<ui::UICommand>
  CreateRequest(UICommandArg arg,
    bool stopOnEntry,
    std::optional<BreakpointBehavior> behaviorSetting,
    const mdbjson::JsonValue &args) noexcept
  {
    IfInvalidArgsReturn(RRLaunch);
    std::string_view traceDir = args["traceDir"];
    return RefPtr<RRLaunch>::MakeShared(std::move(arg), stopOnEntry, behaviorSetting, traceDir);
  }
};

/* static */
RefPtr<ui::UICommand>
Launch::CreateRequest(UICommandArg arg, const mdbjson::JsonValue &args) noexcept
{
  DBGLOG(core, "creating lauch request");

  bool stopOnEntry = false;
  if (args.Contains("stopOnEntry")) {
    stopOnEntry = args["stopOnEntry"];
  }

  auto type = args["type"]->UncheckedGetStringView();
  if (type == kSessionTypePtrace) {
    const auto behaviorSetting = args.Get("breakpointBehavior")
                                   .and_then([](const auto &json) { return json.GetStringView(); })
                                   .transform([](const std::string_view &behavior) {
                                     if (behavior == "Stop all threads"sv) {
                                       return BreakpointBehavior::StopAllThreadsWhenHit;
                                     } else if (behavior == "Stop single thread"sv) {
                                       return BreakpointBehavior::StopOnlyThreadThatHit;
                                     } else {
                                       return BreakpointBehavior::StopAllThreadsWhenHit;
                                     }
                                   })
                                   .value_or(BreakpointBehavior::StopAllThreadsWhenHit);

    return NativeLaunch::CreateRequest(std::move(arg), stopOnEntry, behaviorSetting, args);
  } else if (type == kSessionTypeRr) {
    return RRLaunch::CreateRequest(std::move(arg), stopOnEntry, BreakpointBehavior::StopAllThreadsWhenHit, args);
  }

  PANIC("Unhandled launch session type");
}

struct AttachResponse final : public UIResult
{
  AttachResponse(SessionId processId, bool success, UICommandPtr cmd) noexcept
      : UIResult(success, cmd), mAttachedProcessId(processId)
  {
  }
  ~AttachResponse() noexcept override = default;
  SessionId mAttachedProcessId;

  std::pmr::string
  Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final
  {
    std::pmr::string result{ arenaAllocator };
    result.reserve(256);
    auto outIt = std::back_inserter(result);
    std::format_to(outIt,
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"attach", "body": {{ "processId": {} }} }})",
      seq,
      mRequestSeq,
      mProcessId,
      mAttachedProcessId);
    return result;
  }
};

struct Attach final : public UICommand
{
  static constexpr auto kSessionType = "sessionType"sv;

  Attach(UICommandArg arg, AttachArgs args) noexcept : UICommand{ std::move(arg) }, attachArgs{ args } {}

  ~Attach() override = default;

  void
  Execute() noexcept final
  {
    auto *supervisor = Tracer::Get().SessionAttach(mDebugAdapterManager, attachArgs);
    WriteResponse(AttachResponse{ supervisor->GetProcessId(), true, this });
  }

  AttachArgs attachArgs;
  DEFINE_NAME("attach");
  RequiredArguments({ kSessionType });

  DefineArgTypes({ "port", FieldType::Int },
    { "host", FieldType::String },
    { "pid", FieldType::Int },
    {
      kSessionType,
      FieldType::Enumeration,
      { kSessionTypePtrace, kSessionTypeRr },
    });

  inline static std::vector<InvalidArg>
  ProcessArgs(const mdbjson::JsonValue &args)
  {
    std::vector<InvalidArg> invalid{};
    for (const auto &required : { "processId" }) {
      if (!args.Contains(required)) {
        invalid.push_back({ ArgumentError::Missing("required for ptrace attach"), required });
      } else if (!args.Get(required)->IsNumber()) {
        invalid.push_back({ ArgumentError::RequiredNumberType(), required });
      }
    }
    return invalid;
  }

  static RefPtr<ui::UICommand>
  CreateRequestForPtrace(UICommandArg arg, const mdbjson::JsonValue &args) noexcept
  {
    auto invalid = ProcessArgs(args);
    if (!invalid.empty()) {
      return RefPtr<ui::dap::InvalidArgs>::MakeShared(std::move(arg), "attach", std::move(invalid));
    }

    Pid processId = *args.Get("processId")->GetNumber();
    MDB_ASSERT(processId > 0, "Expect a process id > 0 (technically 1 too, since it's systemd)");
    return RefPtr<Attach>::MakeShared(std::move(arg), PtraceAttachArgs{ processId });
  }

  static RefPtr<ui::UICommand>
  CreateRequest(UICommandArg arg, const mdbjson::JsonValue &args) noexcept
  {
    auto type = args.At(kSessionType)->UncheckedGetStringView();
    MDB_ASSERT(args.Contains("processId"), "Attach arguments had no 'processId' field.");
    if (type == kSessionTypePtrace) {
      return CreateRequestForPtrace(std::move(arg), args);
    } else if (type == kSessionTypeRr) {
      TODO("Multiprocess rr currently handled in UI layer.");
    } else if (type == kSessionTypeGdbRemote) {
      TODO("Removed gdb support, not priority");
    }
    std::vector<InvalidArg> invalid{};
    invalid.emplace_back(ArgumentError::Invalid("invalid session type"), "sessionType"sv);
    return RefPtr<ui::dap::InvalidArgs>::MakeShared(std::move(arg), "attach", std::move(invalid));
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"terminate"}})",
      seq,
      mRequestSeq,
      mProcessId);
    return result;
  }
};

struct Terminate final : public UICommand
{
  Terminate(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~Terminate() override = default;

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();
    target->Disconnect(true);
    return WriteResponse(TerminateResponse{ true, this });
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"threads","body":{{"threads":[{}]}}}})",
      seq,
      mRequestSeq,
      mProcessId,
      JoinFormatIterator{ mThreads, "," });
    return result;
  }

  std::pmr::vector<Thread> mThreads;
};

struct Threads final : public UICommand
{
  Threads(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~Threads() override = default;

  void
  Execute() noexcept final
  {
    auto *target = GetSupervisoOrSendError();
    std::pmr::vector<Thread> threads{ MemoryResource() };
    threads.reserve(target->GetThreads().size());

    target->IterateValidThreads([&](TaskInfo &task) {
      threads.push_back(Thread{ .mThreadId = task.mTid, .mName = task.GetName() });
      return PredicateIterator::Continue;
    });

    return WriteResponse(ThreadsResponse{ true, std::move(threads), this });
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
  void Execute() noexcept final;
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
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"stackTrace","body":{{"stackFrames":[{}]}}}})",
    seq,
    mRequestSeq,
    mProcessId,
    JoinFormatIterator{ stack_frames, "," });
  return result;
}

void
StackTrace::Execute() noexcept
{
  // todo(simon): multiprocessing needs additional work, since DAP does not support it natively.
  auto *target = GetSupervisoOrSendError();
  PROFILE_BEGIN_ARGS("StackTrace", "command", PEARG("seq", mSeq));
  auto task = target->GetTaskByTid(mThreadId);
  if (task == nullptr) {
    std::pmr::string err{ MemoryResource() };
    std::format_to(std::back_inserter(err), "Thread with ID {} not found", mThreadId);
    return WriteResponse(ErrorResponse{ StackTrace::Request, this, std::move(err), {} });
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
  return WriteResponse(StackTraceResponse{ true, this, std::move(stackFrames) });
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"scopes","body":{{"scopes":[{}]}}}})",
      seq,
      mRequestSeq,
      mProcessId,
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

  void
  Execute() noexcept final
  {
    auto ctx = Tracer::GetVariableContext(mFrameId);
    if (!ctx || !ctx->IsValidContext() || ctx->mType != ContextType::Frame) {
      std::pmr::string err{ MemoryResource() };
      std::format_to(std::back_inserter(err), "Invalid variable context for {}", mFrameId);
      return WriteResponse(ErrorResponse{ Request, this, std::move(err), {} });
    }
    auto frame = ctx->GetFrame(mFrameId);
    if (!frame) {
      return WriteResponse(ScopesResponse{ false, this, {} });
    }
    const auto scopes = frame->Scopes();
    return WriteResponse(ScopesResponse{ true, this, scopes });
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
  void Execute() noexcept final;

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

void
Disassemble::Execute() noexcept
{
  if (mAddress) {
    auto *target = GetSupervisoOrSendError();
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
        return WriteResponse(*res);
      }
      remaining -= res->mInstructions.size();
      mInstructionOffset = 0;
    }

    if (remaining > 0) {
      sym::Disassemble(
        target, mAddress.value(), static_cast<u32>(std::abs(mInstructionOffset)), remaining, res->mInstructions);
    }
    return WriteResponse(*res);
  } else {
    return WriteResponse(ErrorResponse{ Request, this, "Address parameter could not be parsed.", std::nullopt });
  }
}

std::pmr::string
DisassembleResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  result.reserve(256 + (256 * mInstructions.size()));
  auto outIt = std::back_inserter(result);
  auto it = std::format_to(outIt,
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"disassemble","body":{{"instructions":[)",
    seq,
    mRequestSeq,
    mProcessId);
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
  void Execute() noexcept final;

  Immutable<std::string> expr;
  Immutable<std::optional<int>> frameId;
  Immutable<EvaluationContext> context;

  DEFINE_NAME("evaluate");
  RequiredArguments({ "expression"sv, "context"sv });
  DefineArgTypes(
    { "expression", FieldType::String }, { "frameId", FieldType::Int }, { "context", FieldType::String });

  static EvaluationContext ParseContext(std::string_view input) noexcept;
  static RefPtr<UICommand> PrepareEvaluateCommand(UICommandArg arg, const mdbjson::JsonValue &args);
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

void
Evaluate::Execute() noexcept
{
  PROFILE_SCOPE_ARGS("Evaluate", "command", PEARG("seq", mSeq));
  switch (context) {
  case EvaluationContext::Watch:
    [[fallthrough]];
  case EvaluationContext::Repl: {
    Allocator alloc{ MemoryResource() };
    auto result = Tracer::Get().EvaluateDebugConsoleExpression(expr, &alloc);
    return WriteResponse(EvaluateResponse{ true, this, {}, result, {}, {} });
  }
  case EvaluationContext::Hover:
    [[fallthrough]];
  case EvaluationContext::Clipboard:
    [[fallthrough]];
  case EvaluationContext::Variables:
    return WriteResponse(ErrorResponse{ Request, this, {}, Message{ "could not evaluate"sv, MemoryResource() } });
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
RefPtr<UICommand>
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

  return RefPtr<ui::dap::Evaluate>::MakeShared(std::move(arg), std::move(expr), frameId, ctx);
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"evaluate","body":{{ "result":"{}", "variablesReference":{} }}}})",
      seq,
      mRequestSeq,
      mProcessId,
      DebugAdapterProtocolString{ *mResult },
      mVariablesReference);
  } else {
    std::format_to(std::back_inserter(evalResponseResult),
      R"({{"seq":0,"request_seq":{},"processId":{},"type":"response","success":false,"command":"evaluate","body":{{ "error":{{ "id": -1, "format": "{}" }} }}}})",
      mRequestSeq,
      mProcessId,
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
  void Execute() noexcept final;
  ErrorResponse *error(std::pmr::string &&msg) noexcept;
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
Variables::error(std::pmr::string &&msg) noexcept
{
  return mCommandAllocator->Allocate<ErrorResponse>(
    Request, this, std::optional<std::pmr::string>{}, Message{ std::move(msg), MemoryResource() });
}

void
Variables::Execute() noexcept
{
  PROFILE_SCOPE_ARGS("Variables", "command", PEARG("seq", mSeq));
  auto requestedContext = Tracer::GetVariableContext(mVariablesReferenceId);
  if (!requestedContext || !requestedContext->IsValidContext()) {
    std::pmr::string msg{ MemoryResource() };
    std::format_to(
      std::back_inserter(msg), "Could not find variable with variablesReference {}", mVariablesReferenceId);
    return WriteResponse(*error(std::move(msg)));
  }
  auto &context = *requestedContext;
  auto frame = context.GetFrame(mVariablesReferenceId);
  if (!frame) {
    std::pmr::string err{ MemoryResource() };
    std::format_to(std::back_inserter(err),
      "Could not find frame that's referenced via variablesReference {}",
      mVariablesReferenceId);
    WriteResponse(*error(std::move(err)));
  }

  switch (context.mType) {
  case ContextType::Frame: {
    std::pmr::string err{ MemoryResource() };
    std::format_to(std::back_inserter(err),
      "Sent a variables request using a reference for a frame is an error.",
      mVariablesReferenceId);

    return WriteResponse(*error(std::move(err)));
  }
  case ContextType::Scope: {
    auto scope = frame->Scope(mVariablesReferenceId);
    switch (scope->type) {
    case ScopeType::Arguments: {
      auto vars =
        context.mSymbolFile->GetVariables(*context.mTask->GetSupervisor(), *frame, sym::VariableSet::Arguments);
      return WriteResponse(VariablesResponse{ true, this, std::move(vars) });
    }
    case ScopeType::Locals: {
      auto vars =
        context.mSymbolFile->GetVariables(*context.mTask->GetSupervisor(), *frame, sym::VariableSet::Locals);
      return WriteResponse(VariablesResponse{ true, this, std::move(vars) });
    }
    case ScopeType::Registers: {
      return WriteResponse(VariablesResponse{ true, this, {} });
    } break;
    }
  } break;
  case ContextType::Variable:
    return WriteResponse(
      VariablesResponse{ true, this, context.mSymbolFile->ResolveVariable(context, mStart, mCount) });
  case ContextType::Global:
    TODO("Global variables not yet implemented support for");
    break;
  }

  std::pmr::string err{ MemoryResource() };
  std::format_to(
    std::back_inserter(err), "Could not find variable with variablesReference {}", mVariablesReferenceId);

  return WriteResponse(*error(std::move(err)));
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
      R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"variables","body":{{"variables":[]}}}})",
      seq,
      mRequestSeq,
      mProcessId);
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
          R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":false,"command":"variables","message":"visualizer failed","body":{{"error":{{"id": -1, "format": "Could not visualize value for '{}'"}} }} }})",
          seq,
          mRequestSeq,
          mProcessId,
          v->mName);
        return result;
      }
    } else {
      MDB_ASSERT(v->GetType()->IsReference(),
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
    R"({{"seq":{},"request_seq":{},"processId":{},"type":"response","success":true,"command":"variables","body":{{"variables":[{}]}}}})",
    seq,
    mRequestSeq,
    mProcessId,
    variables_contents);
  return result;
}

static bool
ValidateRequestFormat(const mdbjson::JsonValue &req) noexcept
{
  const auto missingFields = req.Contains("command") && req.Contains("type") && req.Contains("seq") &&
                             req.Contains("arguments") && req.Contains(kProcessId);
  if (!missingFields) {
    DBGLOG(core, "Request missing fields. Request: {}", req);
    return false;
  }

  const auto correctTypes = req["command"]->IsString() && req["seq"]->IsNumber() && req[kProcessId]->IsNumber();

  if (!correctTypes) {
    DBGLOG(dap, "Base protocol request fields of incorrect type. Request: {}", req);
    return false;
  }

  return true;
}

RefPtr<ui::UICommand>
ParseDebugAdapterCommand(DebugAdapterManager &client, std::string_view packet) noexcept
{
  using namespace ui::dap;

  UICommandArg arg{ 0, std::nullopt, client.AcquireArena() };
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

  DBGLOG(dap, "parsed request: {}", obj);
  std::string_view commandName = obj["command"];

  arg.mSeq = obj["seq"];

  if (obj.Contains("processId")) {
    arg.mProcessId = obj["processId"];
  }

  const auto cmd = ParseCommandType(commandName);
  const mdbjson::JsonValue &args = obj["arguments"];
  switch (cmd) {
  case CommandType::Attach: {
    IfInvalidArgsReturn(Attach);
    return Attach::CreateRequest(std::move(arg), args);
  }
  case CommandType::BreakpointLocations:
    TODO("Command::BreakpointLocations");
  case CommandType::Completions:
    TODO("Command::Completions");
  case CommandType::ConfigurationDone: {
    IfInvalidArgsReturn(ConfigurationDone);
    return RefPtr<ConfigurationDone>::MakeShared(std::move(arg));
  } break;
  case CommandType::Continue: {
    IfInvalidArgsReturn(Continue);

    bool all_threads = false;
    if (args.Contains("singleThread")) {
      const bool b = args["singleThread"];
      all_threads = !b;
    }
    return RefPtr<Continue>::MakeShared(std::move(arg), args["threadId"], all_threads);
  }
  case CommandType::CustomRequest: {
    if (args.Contains("command") && args.Contains("arguments")) {
      std::string_view customCommand = args["command"];
      return ParseCustomRequestCommand(client, std::move(arg), customCommand, args["arguments"]);
    }
    return RefPtr<ui::dap::InvalidArgs>::MakeShared(std::move(arg), "customRequest", MissingOrInvalidArgs{});
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
    return RefPtr<ui::dap::Disassemble>::MakeShared(
      std::move(arg), addr, offset, instructionOffset, instructionCount, false);
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
    return RefPtr<Disconnect>::MakeShared(std::move(arg), restart, terminateDebuggee, suspendDebuggee);
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
    return RefPtr<Initialize>::MakeShared(std::move(arg), args);
  case CommandType::Launch: {
    IfInvalidArgsReturn(Launch);
    return Launch::CreateRequest(std::move(arg), args);
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
    return RefPtr<Next>::MakeShared(std::move(arg), threadId, !singleThread, stepType);
  }
  case CommandType::Pause: {
    IfInvalidArgsReturn(Pause);
    int threadId = args["threadId"];
    return RefPtr<Pause>::MakeShared(std::move(arg), Pause::Args{ threadId });
  }
  case CommandType::ReadMemory: {
    IfInvalidArgsReturn(ReadMemory);

    std::string_view addrString = args["memoryReference"];
    const auto addr = ToAddress(addrString);

    const auto offset = args.Contains("offset") ? i32{ args["offset"] } : 0;
    const u64 count = args["count"];
    return RefPtr<ReadMemory>::MakeShared(std::move(arg), addr, offset, count);
  }
  case CommandType::Restart:
    TODO("Command::Restart");
  case CommandType::RestartFrame:
    TODO("Command::RestartFrame");
  case CommandType::ReverseContinue: {
    IfInvalidArgsReturn(ReverseContinue);
    int threadId = args["threadId"];
    return RefPtr<ReverseContinue>::MakeShared(std::move(arg), threadId);
  }
  case CommandType::Scopes: {
    IfInvalidArgsReturn(Scopes);

    const int frame_id = args["frameId"];
    return RefPtr<Scopes>::MakeShared(std::move(arg), frame_id);
  }
  case CommandType::SetBreakpoints:
    IfInvalidArgsReturn(SetBreakpoints);

    return RefPtr<SetBreakpoints>::MakeShared(std::move(arg), args);
  case CommandType::SetDataBreakpoints:
    TODO("Command::SetDataBreakpoints");
  case CommandType::SetExceptionBreakpoints: {
    IfInvalidArgsReturn(SetExceptionBreakpoints);
    return RefPtr<SetExceptionBreakpoints>::MakeShared(std::move(arg), args);
  }
  case CommandType::SetExpression:
    TODO("Command::SetExpression");
  case CommandType::SetFunctionBreakpoints:
    IfInvalidArgsReturn(SetFunctionBreakpoints);

    return RefPtr<SetFunctionBreakpoints>::MakeShared(std::move(arg), args);
  case CommandType::SetInstructionBreakpoints:
    IfInvalidArgsReturn(SetInstructionBreakpoints);

    return RefPtr<SetInstructionBreakpoints>::MakeShared(std::move(arg), args);
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
    return RefPtr<StackTrace>::MakeShared(std::move(arg), args["threadId"], startFrame, levels, format_);
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

    return RefPtr<StepIn>::MakeShared(std::move(arg), threadId, singleThread, step_type);
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
    return RefPtr<StepOut>::MakeShared(std::move(arg), threadId, !singleThread);
  }
  case CommandType::Terminate:
    IfInvalidArgsReturn(Terminate);

    return RefPtr<Terminate>::MakeShared(std::move(arg));
  case CommandType::TerminateThreads:
    TODO("Command::TerminateThreads");
  case CommandType::Threads:
    IfInvalidArgsReturn(Threads);

    return RefPtr<Threads>::MakeShared(std::move(arg));
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
    return RefPtr<Variables>::MakeShared(std::move(arg), variablesReference, start, count);
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
    auto bytes = mdb::DecodeBase64(data, arg.allocator->GetAllocator());
    if (bytes.empty()) {
      return RefPtr<InvalidArgs>::MakeShared(std::move(arg), "writeMemory", MissingOrInvalidArgs{});
    }
    return RefPtr<WriteMemory>::MakeShared(std::move(arg), addr, offset, std::move(bytes));
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