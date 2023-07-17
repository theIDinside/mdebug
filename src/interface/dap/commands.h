#pragma once
#include "../ui_command.h"
#include "../ui_result.h"
// NOLINTNEXTLINE
#include "../../breakpoint.h"
#include "dap_defs.h"
#include "nlohmann/json.hpp"
#include "types.h"
#include <tuple>
#include <vector>

namespace ui::dap {

#define CTOR(Type)                                                                                                \
  Type(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd)                                          \
  {                                                                                                               \
  }

struct Breakpoint;

struct ContinueResponse final : ui::UIResult
{
  CTOR(ContinueResponse)
  ~ContinueResponse() noexcept = default;
  bool continue_all;
  std::string serialize(int seq) const noexcept final override;
};

struct Continue final : public ui::UICommand
{
  int thread_id;
  bool continue_all;
  Continue(int tid, bool all) noexcept : thread_id(tid), continue_all(all) {}
  ~Continue() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(Continue)
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointType type) noexcept;
  BreakpointType type;
  std::vector<ui::dap::Breakpoint> breakpoints;
  ~SetBreakpointsResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(nlohmann::json &&arguments) noexcept;
  ~SetInstructionBreakpoints() = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(SetInstructionBreakpoints)
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(nlohmann::json &&arguments) noexcept;
  ~SetFunctionBreakpoints() = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(SetInstructionBreakpoints)
};

struct ReadMemoryResponse final : public ui::UIResult
{
  CTOR(ReadMemoryResponse)
  ~ReadMemoryResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
  TPtr<void> first_readable_address;
  u64 unreadable_bytes;
  std::string data_base64;
};

struct ReadMemory final : public ui::UICommand
{
  ReadMemory(TPtr<void> address, int offset, u64 bytes) noexcept;
  ~ReadMemory() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;

  TPtr<void> address;
  int offset;
  u64 bytes;

  DEFINE_NAME(ReadMemory)
};

struct ConfigurationDoneResponse final : public ui::UIResult
{
  CTOR(ConfigurationDoneResponse)
  ~ConfigurationDoneResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone() noexcept = default;
  ~ConfigurationDone() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;

  DEFINE_NAME(ConfigurationDone)
};

struct InitializeResponse final : public ui::UIResult
{
  CTOR(InitializeResponse)
  ~InitializeResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct Initialize final : public ui::UICommand
{
  Initialize(nlohmann::json &&arguments) noexcept;
  ~Initialize() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  nlohmann::json args;
  DEFINE_NAME(Initialize)
};

struct DisconnectResponse final : public UIResult
{
  CTOR(DisconnectResponse)
  ~DisconnectResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct Disconnect final : public UICommand
{
  Disconnect(bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept;
  ~Disconnect() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  bool restart, terminate_tracee, suspend_tracee;
  DEFINE_NAME(Disconnect)
};

struct LaunchResponse final : public UIResult
{
  CTOR(LaunchResponse)
  ~LaunchResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct Launch final : public UICommand
{
  Launch(Path &&program, std::vector<std::string> &&program_args) noexcept;
  ~Launch() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  Path program;
  std::vector<std::string> program_args;
  DEFINE_NAME(Launch)
};

struct TerminateResponse final : public UIResult
{
  CTOR(TerminateResponse)
  ~TerminateResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
};

struct Terminate final : public UICommand
{
  ~Terminate() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(Terminate)
};

struct ThreadsResponse final : public UIResult
{
  CTOR(ThreadsResponse)
  ~ThreadsResponse() noexcept = default;
  std::string serialize(int seq) const noexcept final override;
  std::vector<Thread> threads;
};

struct Threads final : public UICommand
{
  ~Threads() = default;
  UIResultPtr execute(Tracer *tracer) noexcept final override;
  DEFINE_NAME(Threads)
};

ui::UICommand *parse_command(Command cmd, nlohmann::json &&args) noexcept;
}; // namespace ui::dap