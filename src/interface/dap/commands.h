#pragma once
#include <interface/ui_command.h>
#include <interface/ui_result.h>
// NOLINTNEXTLINE
#include "types.h"
#include <breakpoint.h>
#include <nlohmann/json.hpp>
#include <symbolication/disassemble.h>
#include <tuple>
#include <vector>

namespace ui::dap {

#define CTOR(Type)                                                                                                \
  Type(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}

struct Breakpoint;

struct ContinueResponse final : ui::UIResult
{
  CTOR(ContinueResponse);
  ~ContinueResponse() noexcept override = default;
  bool continue_all;
  std::string serialize(int seq) const noexcept final;
};

struct Continue final : public ui::UICommand
{
  int thread_id;
  bool continue_all;
  Continue(std::uint64_t seq, int tid, bool all) noexcept : UICommand(seq), thread_id(tid), continue_all(all) {}
  ~Continue() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(Continue);
};

enum class SteppingGranularity
{
  Instruction,
  Line,
  LogicalBreakpointLocation
};

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

struct NextResponse final : ui::UIResult
{
  CTOR(NextResponse);
  ~NextResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Next final : public ui::UICommand
{
  int thread_id;
  bool continue_all;
  SteppingGranularity granularity;

  Next(std::uint64_t seq, int tid, bool all, SteppingGranularity granularity) noexcept
      : UICommand(seq), thread_id(tid), continue_all(all), granularity(granularity)
  {
  }
  ~Next() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(Next);
};

struct StepOutResponse final : ui::UIResult
{
  CTOR(StepOutResponse);
  ~StepOutResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct StepOut final : public ui::UICommand
{
  int thread_id;
  bool continue_all;
  SteppingGranularity granularity;

  StepOut(std::uint64_t seq, int tid, bool all, SteppingGranularity granularity) noexcept
      : UICommand(seq), thread_id(tid), continue_all(all), granularity(granularity)
  {
  }
  ~StepOut() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(StepOut);
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointType type) noexcept;
  BreakpointType type;
  std::vector<ui::dap::Breakpoint> breakpoints;
  ~SetBreakpointsResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct SetBreakpoints final : public ui::UICommand
{
  SetBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept;
  ~SetBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(SetBreakpoints);
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept;
  ~SetInstructionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(SetInstructionBreakpoints);
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept;
  ~SetFunctionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(SetFunctionBreakpoints);
};

struct ReadMemoryResponse final : public ui::UIResult
{
  CTOR(ReadMemoryResponse);
  ~ReadMemoryResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  AddrPtr first_readable_address;
  u64 unreadable_bytes;
  std::string data_base64;
};

struct ReadMemory final : public ui::UICommand
{
  ReadMemory(std::uint64_t seq, AddrPtr address, int offset, u64 bytes) noexcept;
  ~ReadMemory() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;

  AddrPtr address;
  int offset;
  u64 bytes;

  DEFINE_NAME(ReadMemory);
};

struct ConfigurationDoneResponse final : public ui::UIResult
{
  CTOR(ConfigurationDoneResponse);
  ~ConfigurationDoneResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone(std::uint64_t seq) noexcept : UICommand(seq) {}
  ~ConfigurationDone() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;

  DEFINE_NAME(ConfigurationDone);
};

struct InitializeResponse final : public ui::UIResult
{
  CTOR(InitializeResponse);
  ~InitializeResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Initialize final : public ui::UICommand
{
  Initialize(std::uint64_t seq, nlohmann::json &&arguments) noexcept;
  ~Initialize() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  nlohmann::json args;
  DEFINE_NAME(Initialize);
};

struct DisconnectResponse final : public UIResult
{
  CTOR(DisconnectResponse);
  ~DisconnectResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Disconnect final : public UICommand
{
  Disconnect(std::uint64_t seq, bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept;
  ~Disconnect() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  bool restart, terminate_tracee, suspend_tracee;
  DEFINE_NAME(Disconnect);
};

struct LaunchResponse final : public UIResult
{
  CTOR(LaunchResponse);
  ~LaunchResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Launch final : public UICommand
{
  Launch(std::uint64_t seq, bool stopAtEntry, Path &&program, std::vector<std::string> &&program_args) noexcept;
  ~Launch() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  bool stopAtEntry;
  Path program;
  std::vector<std::string> program_args;
  DEFINE_NAME(Launch);
};

struct TerminateResponse final : public UIResult
{
  CTOR(TerminateResponse);
  ~TerminateResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Terminate final : public UICommand
{
  Terminate(u64 seq) noexcept : UICommand(seq) {}
  ~Terminate() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(Terminate);
};

struct ThreadsResponse final : public UIResult
{
  CTOR(ThreadsResponse);
  ~ThreadsResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  std::vector<Thread> threads;
};

struct Threads final : public UICommand
{
  Threads(u64 seq) noexcept : UICommand(seq) {}
  ~Threads() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(Threads);
};

struct StackTrace final : public UICommand
{
  StackTrace(std::uint64_t seq, int threadId, std::optional<int> startFrame, std::optional<int> levels,
             std::optional<StackTraceFormat> format) noexcept;
  ~StackTrace() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  int threadId;
  std::optional<int> startFrame;
  std::optional<int> levels;
  std::optional<StackTraceFormat> format;
  DEFINE_NAME(StackTrace);
};

struct StackTraceResponse final : public UIResult
{
  CTOR(StackTraceResponse);
  StackTraceResponse(bool success, StackTrace *cmd, std::vector<StackFrame> &&stack_frames) noexcept;
  ~StackTraceResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  std::vector<StackFrame> stack_frames;
};

struct Scopes final : public UICommand
{
  Scopes(std::uint64_t seq, int frameId) noexcept;
  ~Scopes() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  int frameId;
  DEFINE_NAME(Scopes);
};

struct ScopesResponse final : public UIResult
{
  ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept;
  ~ScopesResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  // For now, we only have 3 scopes, Args, Locals, Registers
  std::array<Scope, 3> scopes;
};

struct Variables final : public UICommand
{
  Variables(std::uint64_t seq, int var_ref) noexcept;
  ~Variables() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  int var_ref;
  DEFINE_NAME(Variables);
};

struct VariablesResponse final : public UIResult
{
  VariablesResponse(bool success, Variables *cmd, std::vector<Variable> &&vars) noexcept;
  ~VariablesResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  std::vector<Variable> variables;
};

struct DisassembleResponse final : public UIResult
{
  CTOR(DisassembleResponse);
  ~DisassembleResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  std::vector<sym::Disassembly> instructions;
};

struct Disassemble final : public UICommand
{
  Disassemble(std::uint64_t seq, AddrPtr address, int byte_offset, int ins_offset, int ins_count,
              bool resolve_symbols) noexcept;
  ~Disassemble() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;

  AddrPtr address;
  int byte_offset;
  int ins_offset;
  int ins_count;
  bool resolve_symbols;
  DEFINE_NAME(Disassemble);
};

ui::UICommand *parse_command(std::string &&packet) noexcept;
}; // namespace ui::dap