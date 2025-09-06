/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/typedefs.h>
#include <interface/ui_command.h>
#include <interface/ui_result.h>
#include <json/json.h>
#include <lib/arena_allocator.h>
#include <utils/expected.h>

namespace mdb {

using namespace std::string_view_literals;
enum class BreakpointType : std::uint8_t;

namespace ui::dap {
using ui::UICommand;
using ui::UIResult;
using ui::UIResultPtr;

RefPtr<ui::UICommand> ParseCustomRequestCommand(const DebugAdapterClient &client,
  UICommandArg arg,
  std::string_view cmd_name,
  const mdbjson::JsonValue &json) noexcept;

// Resume all (currently stopped) processes and their tasks
struct ContinueAll final : public ui::UICommand
{
  DEFINE_NAME("continueAll");
  ContinueAll(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~ContinueAll() noexcept override = default;
  void Execute() noexcept final;
};

struct ContinueAllResponse final : UIResult
{
  ~ContinueAllResponse() noexcept override = default;
  std ::pmr ::string Serialize(int seq, std ::pmr ::memory_resource *arenaAllocator) const noexcept final;
  ContinueAllResponse(bool success, UICommandPtr cmd, Tid taskLeader) noexcept
      : UIResult(success, cmd), mTaskLeader(taskLeader)
  {
  }
  Tid mTaskLeader;
};

struct PauseAll final : UICommand
{
  DEFINE_NAME("pauseAll");
  PauseAll(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~PauseAll() noexcept override = default;
  void Execute() noexcept final;
};

struct PauseAllResponse final : UIResult
{
  ~PauseAllResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  PauseAllResponse(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}
};

struct ProcessId
{
  SessionId mPid;
  u32 mDebugSessionId;
};

struct GetProcesses final : public UICommand
{
  using IdContainer = std::vector<ProcessId>;
  DEFINE_NAME("getProcesses");
  GetProcesses(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~GetProcesses() noexcept override = default;
  void Execute() noexcept final;
};

struct GetProcessesResponse final : public UIResult
{
  constexpr GetProcessesResponse(bool success, UICommandPtr cmd, GetProcesses::IdContainer &&processes) noexcept
      : UIResult(success, cmd), mProcesses(std::move(processes))
  {
  }

  ~GetProcessesResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  GetProcesses::IdContainer mProcesses;
};

enum ScriptKind : u8
{
  Inline,
  File
};

struct ImportScript final : public UICommand
{
  DEFINE_NAME("importScript");
  ImportScript(UICommandArg arg, std::string &&scriptSource) noexcept;
  ~ImportScript() noexcept override = default;
  void Execute() noexcept final;
  std::string mSource;
};

struct ImportScriptResponse final : public UIResult
{
  using EvalResult = mdb::Expected<void, std::string>;

  constexpr ImportScriptResponse(bool success, UICommandPtr cmd, EvalResult &&evalResult) noexcept
      : UIResult(success, cmd), mEvaluateResult(std::move(evalResult))
  {
  }

  ~ImportScriptResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  EvalResult mEvaluateResult;
};
} // namespace ui::dap
} // namespace mdb

template <> struct std::formatter<mdb::ui::dap::ProcessId> : Default<mdb::ui::dap::ProcessId>
{
  template <typename FormatContext>
  constexpr auto
  format(const mdb::ui::dap::ProcessId &processId, FormatContext &ctx) const
  {
    auto it = ctx.out();
    return std::format_to(it, R"({{ "pid": {}, "sessionId": {} }})", processId.mPid, processId.mDebugSessionId);
  }
};