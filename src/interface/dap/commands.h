#pragma once
#include <interface/ui_command.h>
#include <interface/ui_result.h>
#include <span>
// NOLINTNEXTLINE
#include "bp.h"
#include "fmt/ranges.h"
#include "types.h"
#include <interface/attach_args.h>
#include <nlohmann/json.hpp>
#include <symbolication/disassemble.h>
#include <typedefs.h>

using namespace std::string_view_literals;
enum class BreakpointType : std::uint8_t;

namespace ui::dap {

#define CTOR(Type)                                                                                                \
  Type(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}

struct Breakpoint;

template <typename... Args>
consteval auto
count_tuple(Args... args)
{
  return std::tuple_size<decltype(std::make_tuple(std::string_view{args}...))>::value;
}

#define ReqArg(TypeName, ...)                                                                                     \
  enum class TypeName##Args : u8{__VA_ARGS__};                                                                    \
  static constexpr std::array<std::string_view, count_tuple(#__VA_ARGS__)> ArgNames =                             \
    std::to_array({#__VA_ARGS__});

#define RequiredArguments(...)                                                                                    \
  static constexpr const auto ReqArgs = std::to_array(__VA_ARGS__);                                               \
  static constexpr const auto &Arguments() noexcept { return ReqArgs; }

#define NoRequiredArgs()                                                                                          \
  static constexpr const std::array<std::string_view, 0> ReqArgs{};                                               \
  static constexpr const std::array<std::string_view, 0> &Arguments() noexcept { return ReqArgs; }

using namespace std::string_view_literals;

enum class FieldType
{
  String,
  Float,
  Int,
  Boolean,
  Enumeration,
  Array
};

struct VerifyResult
{
  Immutable<std::optional<std::pair<ArgumentError, std::string>>> arg_err;

  std::optional<std::pair<ArgumentError, std::string>> &&
  take() && noexcept
  {
    return std::move(arg_err);
  }

  constexpr operator bool() noexcept { return arg_err->has_value(); }
};

struct VerifyField
{
  static constexpr auto CurrentEnumMax = 5;
  std::string_view name;
  FieldType type;
  std::string_view err_msg{""};
  std::array<std::string_view, CurrentEnumMax> enum_values{};
  u8 enum_variants{0};

  constexpr std::span<const std::string_view>
  get_enum_values() const noexcept
  {
    if (enum_variants == 0) {
      return {};
    }

    return std::span(enum_values).subspan(0, enum_variants);
  }

  constexpr VerifyField(std::string_view fieldName, FieldType fieldType) noexcept
      : name(fieldName), type(fieldType)
  {
  }

  consteval VerifyField(std::string_view fieldName, FieldType fieldType,
                        std::array<std::string_view, CurrentEnumMax> enumerations) noexcept
      : name(fieldName), type(fieldType), enum_values(enumerations),
        enum_variants(enumerations.size() - std::count(enumerations.begin(), enumerations.end(), ""))
  {
    if (fieldType != FieldType::Enumeration) {
      throw std::exception();
    }
  }

  constexpr bool
  has_enum_variant(std::string_view value) const noexcept
  {
    for (const auto v : get_enum_values()) {
      if (value == v) {
        return true;
      }
    }
    return false;
  }
};

template <size_t Size> struct VerifyMap
{
  std::array<VerifyField, Size> fields;

  template <typename Json>
  constexpr VerifyResult
  isOK(const Json &j, std::string_view fieldName) const noexcept
  {
    if (const auto it =
          std::find_if(fields.cbegin(), fields.cend(), [&](const auto &f) { return fieldName == f.name; });
        it != std::cend(fields)) {
      switch (it->type) {
      case FieldType::String:
        if (!j.is_string()) {
          return VerifyResult{std::make_pair(ArgumentError::RequiredStringType(), fieldName)};
        }
        break;
      case FieldType::Float:
        if (!j.is_number_float()) {
          return VerifyResult{std::make_pair(ArgumentError::RequiredNumberType(), fieldName)};
        }
        break;
      case FieldType::Int:
        if (!j.is_number_integer()) {
          return VerifyResult{std::make_pair(ArgumentError::RequiredNumberType(), fieldName)};
        }
        break;
      case FieldType::Boolean:
        if (!j.is_boolean()) {
          return VerifyResult{std::make_pair(ArgumentError::RequiredBooleanType(), fieldName)};
        }
        break;
      case FieldType::Enumeration: {
        if (!j.is_string()) {
          return VerifyResult{
            std::make_pair(ArgumentError{.kind = ArgumentErrorKind::InvalidInput,
                                         .description = "Config enumeration values must be of string type"},
                           fieldName)};
        }
        std::string_view value;
        j.get_to(value);
        if (!it->has_enum_variant(value)) {
          return VerifyResult{
            std::make_pair(ArgumentError{.kind = ArgumentErrorKind::InvalidInput,
                                         .description = fmt::format("Invalid variant: '{}'. Valid: {}", value,
                                                                    fmt::join(it->get_enum_values(), "|"))},
                           fieldName)};
        }
        break;
      }
      case FieldType::Array:
        if (!j.is_array()) {
          return VerifyResult{std::make_pair(ArgumentError::RequiredArrayType(), fieldName)};
        }
        break;
      }
      return VerifyResult{std::nullopt};
    } else {
      return VerifyResult{std::nullopt};
    }
  }
};

#define DefineArgTypes(...)                                                                                       \
  static constexpr auto ArgsFieldsArray = std::to_array<VerifyField>({__VA_ARGS__});                              \
  static constexpr VerifyMap<ArgsFieldsArray.size()> ArgTypes{ArgsFieldsArray};                                   \
  template <typename Json>                                                                                        \
  constexpr static auto ValidateArg(std::string_view arg_name, const Json &arg_contents) noexcept                 \
    -> std::optional<InvalidArg>                                                                                  \
  {                                                                                                               \
    if (auto err = ArgTypes.isOK(arg_contents, arg_name); err) {                                                  \
      return std::move(err).take();                                                                               \
    }                                                                                                             \
    return std::nullopt;                                                                                          \
  }

struct Message
{
  std::string format;
  std::unordered_map<std::string, std::string> variables{};
  bool show_user{true};
  std::optional<int> id{};
};

struct ErrorResponse final : ui::UIResult
{
  ErrorResponse(std::string_view command, ui::UICommandPtr cmd, std::optional<std::string> &&short_message,
                std::optional<Message> &&message) noexcept;
  ~ErrorResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;

  std::string_view command;
  std::optional<std::string> short_message;
  std::optional<Message> message;
};

struct ReverseContinueResponse final : ui::UIResult
{
  CTOR(ReverseContinueResponse);
  ~ReverseContinueResponse() noexcept override = default;
  bool continue_all;
  std::string serialize(int seq) const noexcept final;
};

/** ReverseContinue under RR is *always* "continue all"*/
struct ReverseContinue final : ui::UICommand
{
  ReverseContinue(u64 seq, int thread_id) noexcept;
  ~ReverseContinue() noexcept override = default;
  int thread_id;
  UIResultPtr execute() noexcept final;

  DEFINE_NAME("reverseContinue");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
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

  Continue(u64 seq, int tid, bool all) noexcept : UICommand(seq), thread_id(tid), continue_all(all) {}
  ~Continue() override = default;
  UIResultPtr execute() noexcept final;

  DEFINE_NAME("continue");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
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

  Pause(u64 seq, Args args) noexcept : UICommand(seq), pauseArgs(args) {}
  ~Pause() override = default;
  UIResultPtr execute() noexcept final;

  Args pauseArgs;
  DEFINE_NAME("pause");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

enum class SteppingGranularity
{
  Instruction,
  Line,
  LogicalBreakpointLocation
};

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

  Next(u64 seq, int tid, bool all, SteppingGranularity granularity) noexcept
      : UICommand(seq), thread_id(tid), continue_all(all), granularity(granularity)
  {
  }
  ~Next() override = default;
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("next");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

struct StepInResponse final : ui::UIResult
{
  CTOR(StepInResponse);
  ~StepInResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct StepIn final : public ui::UICommand
{
  int thread_id;
  bool singleThread;
  SteppingGranularity granularity;

  StepIn(u64 seq, int thread_id, bool singleThread, SteppingGranularity granularity) noexcept
      : UICommand(seq), thread_id(thread_id), singleThread(singleThread), granularity(granularity)
  {
  }

  ~StepIn() noexcept final = default;
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("stepIn");
  RequiredArguments({"threadId"});
  DefineArgTypes({"threadId", FieldType::Int});
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

  StepOut(u64 seq, int tid, bool all) noexcept : UICommand(seq), thread_id(tid), continue_all(all) {}
  ~StepOut() override = default;
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("stepOut");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointRequestKind type) noexcept;
  BreakpointRequestKind type;
  std::vector<ui::dap::Breakpoint> breakpoints;
  ~SetBreakpointsResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct SetBreakpoints final : public ui::UICommand
{
  SetBreakpoints(u64 seq, nlohmann::json &&arguments) noexcept;
  ~SetBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("setBreakpoints");
  RequiredArguments({"source"sv});
};

struct SetExceptionBreakpoints final : public ui::UICommand
{
  SetExceptionBreakpoints(u64 sequence, nlohmann::json &&args) noexcept;
  ~SetExceptionBreakpoints() override = default;
  UIResultPtr execute() noexcept final;

  Immutable<nlohmann::json> args;

  DEFINE_NAME("setExceptionBreakpoints");
  RequiredArguments({"filters"sv});
  DefineArgTypes({"filters", FieldType::Array});
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(u64 seq, nlohmann::json &&arguments) noexcept;
  ~SetInstructionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("setInstructionBreakpoints");
  RequiredArguments({"breakpoints"sv});
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(u64 seq, nlohmann::json &&arguments) noexcept;
  ~SetFunctionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("setFunctionBreakpoints");
  RequiredArguments({"breakpoints"sv});
};

struct WriteMemoryResponse final : public ui::UIResult
{
  CTOR(WriteMemoryResponse);
  ~WriteMemoryResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  u64 bytes_written;
};

struct WriteMemory final : public ui::UICommand
{
  WriteMemory(u64 seq, std::optional<AddrPtr> address, int offset, std::vector<u8> &&bytes) noexcept;
  ~WriteMemory() override = default;
  UIResultPtr execute() noexcept final;

  std::optional<AddrPtr> address;
  int offset;
  std::vector<u8> bytes;

  DEFINE_NAME("writeMemory");
  RequiredArguments({"memoryReference"sv, "data"sv});
  DefineArgTypes({"memoryReference", FieldType::String}, {"data", FieldType::String}, {"offset", FieldType::Int});
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
  ReadMemory(u64 seq, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept;
  ~ReadMemory() override = default;
  UIResultPtr execute() noexcept final;

  std::optional<AddrPtr> address;
  int offset;
  u64 bytes;

  DEFINE_NAME("readMemory");
  RequiredArguments({"memoryReference"sv, "count"sv});
  DefineArgTypes({"memoryReference", FieldType::String}, {"count", FieldType::Int}, {"offset", FieldType::Int});
};

struct ConfigurationDoneResponse final : public ui::UIResult
{
  CTOR(ConfigurationDoneResponse);
  ~ConfigurationDoneResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone(u64 seq) noexcept : UICommand(seq) {}
  ~ConfigurationDone() override = default;
  UIResultPtr execute() noexcept final;

  DEFINE_NAME("configurationDone");
  NoRequiredArgs();
};

struct InitializeResponse final : public ui::UIResult
{
  CTOR(InitializeResponse);
  InitializeResponse(bool rrsession, bool ok, UICommandPtr cmd) noexcept;
  ~InitializeResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;

  bool RRSession;
};

struct Initialize final : public ui::UICommand
{
  Initialize(u64 seq, nlohmann::json &&arguments) noexcept;
  ~Initialize() override = default;
  UIResultPtr execute() noexcept final;
  nlohmann::json args;
  DEFINE_NAME("initialize");
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
  Disconnect(u64 seq, bool restart, bool terminate_debuggee, bool suspend_debuggee) noexcept;
  ~Disconnect() override = default;
  UIResultPtr execute() noexcept final;
  bool restart, terminate_tracee, suspend_tracee;
  DEFINE_NAME("disconnect");
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
  Launch(u64 seq, bool stopAtEntry, Path &&program, std::vector<std::string> &&program_args) noexcept;
  ~Launch() override = default;
  UIResultPtr execute() noexcept final;
  bool stopOnEntry;
  Path program;
  std::vector<std::string> program_args;
  DEFINE_NAME("launch");
  RequiredArguments({"program"sv});
  DefineArgTypes({"program", FieldType::String});
};

struct AttachResponse final : public UIResult
{
  CTOR(AttachResponse);
  ~AttachResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
};

struct Attach final : public UICommand
{
  Attach(u64 seq, AttachArgs &&args) noexcept;
  ~Attach() override = default;
  UIResultPtr execute() noexcept final;

  AttachArgs attachArgs;
  DEFINE_NAME("attach");
  RequiredArguments({"type"});

  DefineArgTypes({"port", FieldType::Int}, {"host", FieldType::String}, {"pid", FieldType::Int},
                 {"type", FieldType::Enumeration, {"ptrace"sv, "gdbremote"sv, "rr"}});

  // Attach gets a `create` function because in the future, constructing this command will be much more complex
  // than most other commands, due to the fact that gdbs remote protocol has a ton of settings, some of which are
  // bat shit crazy in 2024.
  static Attach *
  create(uint64_t seq, const nlohmann::basic_json<> &args)
  {
    std::string_view type;
    args.at("type").get_to(type);
    if (type == "ptrace") {
      Pid pid = args.at("pid");
      return new Attach{seq, PtraceAttachArgs{.pid = pid}};
    } else {
      int port = args.at("port");
      std::string host = args.at("host");
      bool allstop = true;
      if (args.contains("allstop") && args.at("allstop").is_boolean()) {
        allstop = args.at("allstop");
      }
      RemoteType remote_type = type == "rr" ? RemoteType::RR : RemoteType::GDB;

      return new Attach{seq,
                        GdbRemoteAttachArgs{.host = host, .port = port, .allstop = allstop, .type = remote_type}};
    };
  }
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
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("terminate");
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
  UIResultPtr execute() noexcept final;
  DEFINE_NAME("threads");
  NoRequiredArgs();
};

struct StackTrace final : public UICommand
{
  StackTrace(u64 seq, int threadId, std::optional<int> startFrame, std::optional<int> levels,
             std::optional<StackTraceFormat> format) noexcept;
  ~StackTrace() override = default;
  UIResultPtr execute() noexcept final;
  int threadId;
  std::optional<int> startFrame;
  std::optional<int> levels;
  std::optional<StackTraceFormat> format;
  DEFINE_NAME("stackTrace");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
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
  Scopes(u64 seq, int frameId) noexcept;
  ~Scopes() override = default;
  UIResultPtr execute() noexcept final;
  int frameId;
  DEFINE_NAME("scopes");
  RequiredArguments({"frameId"sv});
  DefineArgTypes({"frameId", FieldType::Int});
};

struct ScopesResponse final : public UIResult
{
  ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept;
  ~ScopesResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  // For now, we only have 3 scopes, Args, Locals, Registers
  std::array<Scope, 3> scopes;
};

enum class EvaluationContext
{
  Watch,
  Repl,
  Hover,
  Clipboard,
  Variables
};

struct Evaluate final : public UICommand
{
  Evaluate(u64 seq, std::string &&expression, std::optional<int> frameId,
           std::optional<EvaluationContext> context) noexcept;
  ~Evaluate() noexcept final = default;
  UIResultPtr execute() noexcept final;

  Immutable<std::string> expr;
  Immutable<std::optional<int>> frameId;
  Immutable<EvaluationContext> context;

  DEFINE_NAME("evaluate");
  RequiredArguments({"expression"sv});
  DefineArgTypes({"expression", FieldType::String}, {"frameId", FieldType::Int});

  static std::optional<EvaluationContext> parse_context(std::string_view input) noexcept;
};

struct EvaluateResponse final : public UIResult
{
  EvaluateResponse(bool success, Evaluate *cmd, std::optional<int> variablesReference, std::string &&result,
                   std::optional<std::string> &&type, std::optional<std::string> &&memoryReference) noexcept;
  ~EvaluateResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;

  std::string result;
  std::optional<std::string> type;
  int variablesReference;
  std::optional<std::string> memoryReference;
};

struct Variables final : public UICommand
{
  Variables(u64 seq, int var_ref, std::optional<u32> start, std::optional<u32> count) noexcept;
  ~Variables() override = default;
  UIResultPtr execute() noexcept final;
  ErrorResponse *error(std::string &&msg) noexcept;
  int var_ref;
  std::optional<u32> start;
  std::optional<u32> count;
  DEFINE_NAME("variables");
  RequiredArguments({"variablesReference"sv});
  DefineArgTypes({"variablesReference", FieldType::Int}, {"start", FieldType::Int}, {"count", FieldType::Int});
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
  Disassemble(u64 seq, std::optional<AddrPtr> address, int byte_offset, int ins_offset, int ins_count,
              bool resolve_symbols) noexcept;
  ~Disassemble() override = default;
  UIResultPtr execute() noexcept final;

  std::optional<AddrPtr> address;
  int byte_offset;
  int ins_offset;
  int ins_count;
  bool resolve_symbols;
  DEFINE_NAME("disassemble");
  RequiredArguments({"memoryReference", "instructionCount"});
  DefineArgTypes({"memoryReference", FieldType::String}, {"instructionCount", FieldType::Int},
                 {"instructionOffset", FieldType::Int}, {"offset", FieldType::Int});
};

struct InvalidArgsResponse final : public UIResult
{
  InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgsResponse() noexcept override = default;
  std::string serialize(int seq) const noexcept final;
  std::string_view command;
  MissingOrInvalidArgs missing_or_invalid;
};

template <typename T>
concept HasName = requires(T t) {
  {
    T::Request
  } -> std::convertible_to<std::string_view>;
};

struct InvalidArgs final : public UICommand
{
  InvalidArgs(u64 seq, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgs() override = default;

  UIResultPtr execute() noexcept final;

  ArgumentErrorKind kind;
  std::string_view command;
  MissingOrInvalidArgs missing_arguments;

  DEFINE_NAME("disassemble");
};

ui::UICommand *parse_command(std::string &&packet) noexcept;

template <typename Derived, typename JsonArgs>
static constexpr auto
Validate(uint64_t seq, const JsonArgs &args) -> InvalidArgs *
{
  if (auto &&missing = UICommand::check_args<Derived>(args); missing) {
    return new ui::dap::InvalidArgs{seq, Derived::Request, std::move(missing.value())};
  } else {
    return nullptr;
  }
}
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