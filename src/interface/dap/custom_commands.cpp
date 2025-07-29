/** LICENSE TEMPLATE */
#include "custom_commands.h"
#include "fmt/ranges.h"
#include "interface/dap/events.h"
#include "interface/dap/interface.h"
#include "invalid.h"
#include "mdbjs/mdbjs.h"
#include "supervisor.h"
#include "tracer.h"

namespace mdb::ui::dap {
ui::UICommand *
ParseCustomRequestCommand(const DebugAdapterClient &client, UICommandArg arg, const std::string &cmd_name,
                          const nlohmann::basic_json<> &json) noexcept
{
  if (cmd_name == "continueAll") {
    return new ContinueAll{arg};
  }
  if (cmd_name == "pauseAll") {
    return new PauseAll{arg};
  }
  if (cmd_name == "getProcesses") {
    return new GetProcesses{arg};
  }
  return new InvalidArgs{arg, cmd_name, {}};
}

UIResultPtr
ContinueAll::Execute() noexcept
{
  auto target = GetSupervisor();
  ASSERT(target, "Target must not be null");
  auto res = new ContinueAllResponse{true, this, target->TaskLeaderTid()};
  std::vector<Tid> resumedThreads{};
  // N.B: it's unfortunate that VSCode doesn't honor the "allThreadsContinued" field on a continued event
  // because merely sending 1 continued event for a thread with that flag set, doesn't update the UI. File bug with
  // vscode. instead we have to re-factor resume target to report the resumed threads.
  auto result = target->ResumeTarget(
    tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess, -1}, &resumedThreads);
  res->success = result;
  if (result) {
    for (const auto &tid : resumedThreads) {
      mDAPClient->PushDelayedEvent(new ContinuedEvent{mPid, tid, true});
    }
  }
  return res;
}

std::pmr::string
ContinueAllResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"continueAll","body":{{"threadId":{}}}}})",
    seq, requestSeq, success, mTaskLeader);
  return result;
}

UIResultPtr
PauseAll::Execute() noexcept
{
  auto target = GetSupervisor();
  auto tid = target->TaskLeaderTid();
  target->StopAllTasks(target->GetTaskByTid(target->TaskLeaderTid()), [client = mDAPClient, tid, pid = mPid]() {
    client->PostDapEvent(new StoppedEvent{pid, StoppedReason::Pause, "Paused", tid, {}, "Paused all", true});
  });
  auto res = new PauseAllResponse{true, this};
  return res;
}

std::pmr::string
PauseAllResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  fmt::format_to(std::back_inserter(result),
                 R"({{"seq":{},"request_seq":{},"type":"response","success":{},"command":"pauseAll"}})", seq,
                 requestSeq, success);
  return result;
}

ImportScript::ImportScript(UICommandArg arg, std::string &&scriptSource) noexcept
    : UICommand(arg), mSource(std::move(scriptSource))
{
}

UIResultPtr
ImportScript::Execute() noexcept
{
  TODO("ImportScript::Execute() noexcept");
  auto &i = Tracer::GetScriptingInstance();
  return new ImportScriptResponse{true, this, i.EvaluateJavascriptString(mSource)};
}

std::pmr::string
ImportScriptResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(512);

  if (mEvaluateResult) {
    fmt::format_to(
      std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"importScript","body":{{"evaluatedOk":true}}}})",
      seq, requestSeq);
  } else {
    fmt::format_to(
      std::back_inserter(result),
      R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"importScript","body":{{"evaluatedOk":false, "error": {}}}}})",
      seq, requestSeq, mEvaluateResult.error());
  }
  return result;
}
UIResultPtr
GetProcesses::Execute() noexcept
{
  IdContainer result{};
  for (auto tc : Tracer::Get().GetAllProcesses()) {
    result.emplace_back(tc->TaskLeaderTid(), tc->SessionId());
  }

  return new GetProcessesResponse{true, this, std::move(result)};
}

std::pmr::string
GetProcessesResponse::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(512);
  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"request_seq":{},"type":"response","success":true,"command":"getProcesses","body":{{ "processes": [{}] }}}})",
    seq, requestSeq, fmt::join(mProcesses, ", "));
  return result;
}

} // namespace mdb::ui::dap