/** LICENSE TEMPLATE */
#include "custom_commands.h"

// mdb
#include <interface/dap/events.h>
#include <interface/dap/interface.h>
#include <interface/dap/invalid.h>
#include <interface/ui_command.h>
#include <supervisor.h>
#include <tracer.h>
#include <utils/format_utils.h>

namespace mdb::ui::dap {
// TODO: ParseCustomRequestCommand will almost certainly take DebugAdapterClient at some point (to get an
// allocator.)

RefPtr<ui::UICommand>
ParseCustomRequestCommand(
  const DebugAdapterClient &, UICommandArg arg, std::string_view cmd_name, const mdbjson::JsonValue &) noexcept
{
  if (cmd_name == "continueAll") {
    return RefPtr<ContinueAll>::MakeShared(std::move(arg));
  }
  if (cmd_name == "pauseAll") {
    return RefPtr<PauseAll>::MakeShared(std::move(arg));
  }
  if (cmd_name == "getProcesses") {
    return RefPtr<GetProcesses>::MakeShared(std::move(arg));
  }
  return RefPtr<InvalidArgs>::MakeShared(std::move(arg), cmd_name, MissingOrInvalidArgs{});
}

void
ContinueAll::Execute() noexcept
{
  auto target = GetSupervisor();
  MDB_ASSERT(target, "Target must not be null");
  auto res = Allocate<ContinueAllResponse>(true, this, target->TaskLeaderTid());
  std::vector<Tid> resumedThreads{};
  // N.B: it's unfortunate that VSCode doesn't honor the "allThreadsContinued" field on a continued event
  // because merely sending 1 continued event for a thread with that flag set, doesn't update the UI. File bug with
  // vscode. instead we have to re-factor resume target to report the resumed threads.
  auto result = target->ResumeTarget(tc::RunType::Continue, &resumedThreads);
  res->mSuccess = result;
  if (result) {
    for (const auto &tid : resumedThreads) {
      mDAPClient->PushDelayedEvent(new ContinuedEvent{ mSessionId, tid, true });
    }
  }
  return WriteResponse(*res);
}

std::pmr::string
ContinueAllResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  std::format_to(std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"continueAll","body":{{"threadId":{}}}}})",
    seq,
    mRequestSeq,
    mSuccess,
    mTaskLeader);
  return result;
}

void
PauseAll::Execute() noexcept
{
  auto target = GetSupervisor();
  auto tid = target->TaskLeaderTid();
  target->StopAllTasks([client = mDAPClient, tid, sessionId = mSessionId]() {
    client->PostDapEvent(
      new StoppedEvent{ sessionId, StoppedReason::Pause, "Paused", tid, {}, "Paused all", true });
  });
  return WriteResponse(PauseAllResponse{ true, this });
}

std::pmr::string
PauseAllResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  std::format_to(std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"pauseAll"}})",
    seq,
    mRequestSeq,
    mSuccess);
  return result;
}

ImportScript::ImportScript(UICommandArg arg, std::string &&scriptSource) noexcept
    : UICommand(std::move(arg)), mSource(std::move(scriptSource))
{
}

void
ImportScript::Execute() noexcept
{
  TODO("ImportScript::Execute() noexcept");
}

std::pmr::string
ImportScriptResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  result.reserve(512);

  if (mEvaluateResult) {
    std::format_to(std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"importScript","body":{{"evaluatedOk":true}}}})",
      seq,
      mRequestSeq);
  } else {
    std::format_to(std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"importScript","body":{{"evaluatedOk":false, "error": {}}}}})",
      seq,
      mRequestSeq,
      mEvaluateResult.error());
  }
  return result;
}

void
GetProcesses::Execute() noexcept
{
  IdContainer result{};
  for (auto tc : Tracer::Get().GetAllProcesses()) {
    result.emplace_back(tc->TaskLeaderTid(), tc->GetSessionId());
  }

  return WriteResponse(GetProcessesResponse{ true, this, std::move(result) });
}

std::pmr::string
GetProcessesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  result.reserve(512);
  std::format_to(std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"getProcesses","body":{{ "processes": [{}] }}}})",
    seq,
    mRequestSeq,
    JoinFormatIterator{ mProcesses, ", " });
  return result;
}

} // namespace mdb::ui::dap