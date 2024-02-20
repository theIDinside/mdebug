#pragma once
#include <interface/ui_command.h>
#include <interface/ui_result.h>
// NOLINTNEXTLINE
#include "types.h"
#include <breakpoint.h>
#include <nlohmann/json.hpp>
#include <symbolication/disassemble.h>
#include <tuple>
#include <utility>
#include <vector>

using namespace std::string_view_literals;

namespace ui::dap {

#define CTOR(Type)                                                                                                \
  Type(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}

struct Breakpoint;

#define RequiredArguments(...)                                                                                    \
  static constexpr const auto ReqArgs = std::to_array(__VA_ARGS__);                                               \
  static constexpr const auto &Arguments() noexcept { return ReqArgs; }

#define NoRequiredArgs()                                                                                          \
  static constexpr const std::array<std::string_view, 0> ReqArgs{};                                               \
  static constexpr const std::array<std::string_view, 0> &Arguments() noexcept { return ReqArgs; }

struct Message
{
  std::string format;
  std::unordered_map<std::string, std::string> variables;
  bool show_user;
};

struct ErrorResponse final : ui::UIResult
{
  ErrorResponse(std::string &&command, ui::UICommandPtr cmd, std::optional<std::string> &&short_message,
                std::optional<Message> &&message) noexcept;
  ~ErrorResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;

  std::string command;
  std::optional<std::string> short_message;
  std::optional<Message> message;
};

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
  RequiredArguments({"threadId"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "threadId") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
};

struct PauseResponse final : ui::UIResult
{
  CTOR(PauseResponse);
  ~PauseResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Pause final : public ui::UICommand
{
  struct Args
  {
    int threadId;
  };

  Pause(std::uint64_t seq, Args args) noexcept : UICommand(seq), pauseArgs(args) {}
  ~Pause() override = default;
  UIResultPtr execute(Tracer *tc) noexcept final;

  Args pauseArgs;
  DEFINE_NAME(Pause);
  RequiredArguments({"threadId"sv});
  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "threadId") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
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
  RequiredArguments({"threadId"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "threadId") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
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

  StepOut(std::uint64_t seq, int tid, bool all) noexcept : UICommand(seq), thread_id(tid), continue_all(all) {}
  ~StepOut() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(StepOut);
  RequiredArguments({"threadId"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "threadId") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
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
  RequiredArguments({"source"sv});
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept;
  ~SetInstructionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(SetInstructionBreakpoints);
  RequiredArguments({"breakpoints"sv});
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(std::uint64_t seq, nlohmann::json &&arguments) noexcept;
  ~SetFunctionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  DEFINE_NAME(SetFunctionBreakpoints);
  RequiredArguments({"breakpoints"sv});
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
  ReadMemory(std::uint64_t seq, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept;
  ~ReadMemory() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;

  std::optional<AddrPtr> address;
  int offset;
  u64 bytes;

  DEFINE_NAME(ReadMemory);
  RequiredArguments({"memoryReference"sv, "count"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "memoryReference") {
      if (!arg_contents.is_string()) { // "Argument required to be a number type"
        return std::make_pair(ArgumentError::RequiredStringType(), std::string{arg_name});
      }
    }

    if (arg_name == "count" || arg_name == "offset") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
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
  NoRequiredArgs();
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
  NoRequiredArgs();
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
  NoRequiredArgs();
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
  RequiredArguments({"program"sv});
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
  NoRequiredArgs();
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
  NoRequiredArgs();
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
  RequiredArguments({"threadId"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "threadId") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
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
  RequiredArguments({"frameId"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "frameId") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
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
  Variables(std::uint64_t seq, int var_ref, std::optional<u32> start, std::optional<u32> count) noexcept;
  ~Variables() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;
  int var_ref;
  std::optional<u32> start;
  std::optional<u32> count;
  DEFINE_NAME(Variables);
  RequiredArguments({"variablesReference"sv});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "variablesReference" || arg_name == "start" || arg_name == "count") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
};

struct VariablesResponse final : public UIResult
{
  VariablesResponse(bool success, Variables *cmd, std::vector<Variable> &&vars) noexcept;
  ~VariablesResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  int requested_reference;
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
  Disassemble(std::uint64_t seq, std::optional<AddrPtr> address, int byte_offset, int ins_offset, int ins_count,
              bool resolve_symbols) noexcept;
  ~Disassemble() override = default;
  UIResultPtr execute(Tracer *tracer) noexcept final;

  std::optional<AddrPtr> address;
  int byte_offset;
  int ins_offset;
  int ins_count;
  bool resolve_symbols;
  DEFINE_NAME(Disassemble);
  RequiredArguments({"memoryReference", "instructionCount"});

  template <typename Json>
  constexpr static auto
  ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept -> std::optional<InvalidArg>
  {
    if (arg_name == "memoryReference") {
      if (!arg_contents.is_string()) {
        return std::make_pair(ArgumentError::RequiredStringType(), std::string{arg_name});
      }
    }

    if (arg_name == "instructionCount" || arg_name == "instructionOffset" || arg_name == "offset") {
      if (!arg_contents.is_number()) {
        return std::make_pair(ArgumentError::RequiredNumberType(), std::string{arg_name});
      }
    }
    return std::nullopt;
  }
};

struct InvalidArgsResponse final : public UIResult
{
  InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgsResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  std::string_view command;
  MissingOrInvalidArgs missing_arguments;
};

struct InvalidArgs final : public UICommand
{
  InvalidArgs(std::uint64_t seq, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgs() override = default;

  UIResultPtr execute(Tracer *tracer) noexcept final;

  ArgumentErrorKind kind;
  std::string_view command;
  MissingOrInvalidArgs missing_arguments;

  DEFINE_NAME(Disassemble);
};

ui::UICommand *parse_command(std::string &&packet) noexcept;
}; // namespace ui::dap

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

    return fmt::format_to(ctx.out(), R"({{ "format": "{}", "variables": {{ {} }}, "showUser": "{}" }})",
                          msg.format, fmt::join(buf, ""), msg.show_user);
  }
};

} // namespace fmt