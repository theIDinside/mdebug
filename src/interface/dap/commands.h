/** LICENSE TEMPLATE */
#pragma once
#include <interface/ui_command.h>
#include <interface/ui_result.h>
#include <memory_resource>
#include <span>
// NOLINTNEXTLINE
#include "bp.h"
#include "fmt/ranges.h"
#include "interface/dap/interface.h"
#include "types.h"
#include <interface/attach_args.h>
#include <lib/arena_allocator.h>
#include <nlohmann/json.hpp>
#include <symbolication/disassemble.h>
#include <typedefs.h>

namespace mdb {
namespace fmt = ::fmt;

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

  constexpr
  operator bool() noexcept
  {
    return arg_err->has_value();
  }
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
  constexpr static auto ValidateArg(std::string_view arg_name,                                                    \
                                    const Json &arg_contents) noexcept -> std::optional<InvalidArg>               \
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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  std::string_view command;
  std::optional<std::string> short_message;
  std::optional<Message> message;
};

struct ReverseContinueResponse final : ui::UIResult
{
  CTOR(ReverseContinueResponse);
  ~ReverseContinueResponse() noexcept override = default;
  bool continue_all;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

/** ReverseContinue under RR is *always* "continue all"*/
struct ReverseContinue final : ui::UICommand
{
  ReverseContinue(u64 seq, int thread_id) noexcept;
  ~ReverseContinue() noexcept override = default;
  int thread_id;
  UIResultPtr Execute() noexcept final;

  DEFINE_NAME("reverseContinue");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

struct ContinueResponse final : ui::UIResult
{
  CTOR(ContinueResponse);
  ~ContinueResponse() noexcept override = default;
  bool continue_all;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Continue final : public ui::UICommand
{
  int thread_id;
  bool continue_all;

  Continue(u64 seq, int tid, bool all) noexcept : UICommand(seq), thread_id(tid), continue_all(all) {}
  ~Continue() override = default;
  UIResultPtr Execute() noexcept final;

  DEFINE_NAME("continue");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

// Resume all (currently stopped) processes and their tasks
struct ContinueAll final : public ui::UICommand
{
  DEFINE_NAME("continueAll");
  ContinueAll(u64 seq) noexcept : UICommand(seq) {}
  ~ContinueAll() noexcept override = default;
  UIResultPtr Execute() noexcept final;
};

struct ContinueAllResponse final : ui::UIResult
{
  ~ContinueAllResponse() noexcept override = default;
  std ::pmr ::string Serialize(int seq, std ::pmr ::memory_resource *arenaAllocator) const noexcept final;
  ContinueAllResponse(bool success, UICommandPtr cmd, Tid taskLeader) noexcept
      : UIResult(success, cmd), mTaskLeader(taskLeader)
  {
  }
  Tid mTaskLeader;
};

struct PauseAll final : ui::UICommand
{
  DEFINE_NAME("pauseAll");
  PauseAll(u64 seq) noexcept : UICommand(seq) {}
  ~PauseAll() noexcept override = default;
  UIResultPtr Execute() noexcept final;
};

struct PauseAllResponse final : ui::UIResult
{
  ~PauseAllResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  PauseAllResponse(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}
};

struct PauseResponse final : ui::UIResult
{
  ~PauseResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  PauseResponse(bool success, UICommandPtr cmd) noexcept : UIResult(success, cmd) {}
};

struct Pause final : public ui::UICommand
{
  struct Args
  {
    int threadId;
  };

  Pause(u64 seq, Args args) noexcept : UICommand(seq), pauseArgs(args) {}
  ~Pause() override = default;
  UIResultPtr Execute() noexcept final;

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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
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
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("next");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

struct StepInResponse final : ui::UIResult
{
  CTOR(StepInResponse);
  ~StepInResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
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
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("stepIn");
  RequiredArguments({"threadId"});
  DefineArgTypes({"threadId", FieldType::Int});
};

struct StepOutResponse final : ui::UIResult
{
  CTOR(StepOutResponse);
  ~StepOutResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct StepOut final : public ui::UICommand
{
  int thread_id;
  bool continue_all;

  StepOut(u64 seq, int tid, bool all) noexcept : UICommand(seq), thread_id(tid), continue_all(all) {}
  ~StepOut() override = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("stepOut");
  RequiredArguments({"threadId"sv});
  DefineArgTypes({"threadId", FieldType::Int});
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointRequestKind type) noexcept;
  std::vector<ui::dap::Breakpoint> breakpoints;
  BreakpointRequestKind mType;
  ~SetBreakpointsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct SetBreakpoints final : public ui::UICommand
{
  SetBreakpoints(u64 seq, nlohmann::json &&arguments) noexcept;
  ~SetBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("setBreakpoints");
  RequiredArguments({"source"sv});
};

struct SetExceptionBreakpoints final : public ui::UICommand
{
  SetExceptionBreakpoints(u64 sequence, nlohmann::json &&args) noexcept;
  ~SetExceptionBreakpoints() override = default;
  UIResultPtr Execute() noexcept final;

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
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("setInstructionBreakpoints");
  RequiredArguments({"breakpoints"sv});
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(u64 seq, nlohmann::json &&arguments) noexcept;
  ~SetFunctionBreakpoints() override = default;
  nlohmann::json args;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("setFunctionBreakpoints");
  RequiredArguments({"breakpoints"sv});
};

struct WriteMemoryResponse final : public ui::UIResult
{
  CTOR(WriteMemoryResponse);
  ~WriteMemoryResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  u64 bytes_written;
};

struct WriteMemory final : public ui::UICommand
{
  WriteMemory(u64 seq, std::optional<AddrPtr> address, int offset, std::vector<u8> &&bytes) noexcept;
  ~WriteMemory() override = default;
  UIResultPtr Execute() noexcept final;

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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  AddrPtr first_readable_address;
  u64 unreadable_bytes;
  std::string data_base64;
};

struct ReadMemory final : public ui::UICommand
{
  ReadMemory(u64 seq, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept;
  ~ReadMemory() override = default;
  UIResultPtr Execute() noexcept final;

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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone(u64 seq) noexcept : UICommand(seq) {}
  ~ConfigurationDone() override = default;
  UIResultPtr Execute() noexcept final;

  DEFINE_NAME("configurationDone");
  NoRequiredArgs();
};

struct InitializeResponse final : public ui::UIResult
{
  CTOR(InitializeResponse);
  InitializeResponse(bool rrsession, bool ok, UICommandPtr cmd) noexcept;
  ~InitializeResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  bool RRSession;
};

struct Initialize final : public ui::UICommand
{
  Initialize(u64 seq, nlohmann::json &&arguments) noexcept;
  ~Initialize() override = default;
  UIResultPtr Execute() noexcept final;
  nlohmann::json args;
  DEFINE_NAME("initialize");
  NoRequiredArgs();
};

struct DisconnectResponse final : public UIResult
{
  CTOR(DisconnectResponse);
  ~DisconnectResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Disconnect final : public UICommand
{
  Disconnect(u64 seq, bool restart, bool terminateTracee, bool suspendTracee) noexcept;
  ~Disconnect() override = default;
  UIResultPtr Execute() noexcept final;
  bool restart, mTerminateTracee, mSuspendTracee;
  DEFINE_NAME("disconnect");
  NoRequiredArgs();
};

struct LaunchResponse final : public UIResult
{
  CTOR(LaunchResponse);
  ~LaunchResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Launch final : public UICommand
{
  Launch(u64 seq, bool stopAtEntry, Path &&program, std::vector<std::string> &&program_args,
         std::optional<BreakpointBehavior> breakpointBehavior) noexcept;
  ~Launch() override = default;
  UIResultPtr Execute() noexcept final;
  bool mStopOnEntry;
  Path mProgram;
  std::vector<std::string> mProgramArgs;
  std::optional<BreakpointBehavior> mBreakpointBehavior;
  DEFINE_NAME("launch");
  RequiredArguments({"program"sv});
  DefineArgTypes({"program", FieldType::String});
};

struct AttachResponse final : public UIResult
{
  CTOR(AttachResponse);
  ~AttachResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Attach final : public UICommand
{
  Attach(u64 seq, AttachArgs &&args) noexcept;
  ~Attach() override = default;
  UIResultPtr Execute() noexcept final;

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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Terminate final : public UICommand
{
  Terminate(u64 seq) noexcept : UICommand(seq) {}
  ~Terminate() override = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("terminate");
  NoRequiredArgs();
};

struct ThreadsResponse final : public UIResult
{
  CTOR(ThreadsResponse);
  ~ThreadsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::vector<Thread> threads;
};

struct Threads final : public UICommand
{
  Threads(u64 seq) noexcept : UICommand(seq) {}
  ~Threads() override = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("threads");
  NoRequiredArgs();
};

struct StackTrace final : public UICommand
{
  StackTrace(u64 seq, int threadId, std::optional<int> startFrame, std::optional<int> levels,
             std::optional<StackTraceFormat> format) noexcept;
  ~StackTrace() override = default;
  UIResultPtr Execute() noexcept final;
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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::vector<StackFrame> stack_frames;
};

struct Scopes final : public UICommand
{
  Scopes(u64 seq, int frameId) noexcept;
  ~Scopes() override = default;
  UIResultPtr Execute() noexcept final;
  int frameId;
  DEFINE_NAME("scopes");
  RequiredArguments({"frameId"sv});
  DefineArgTypes({"frameId", FieldType::Int});
};

struct ScopesResponse final : public UIResult
{
  ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept;
  ~ScopesResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
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
  UIResultPtr Execute() noexcept final;

  Immutable<std::string> expr;
  Immutable<std::optional<int>> frameId;
  Immutable<EvaluationContext> context;

  DEFINE_NAME("evaluate");
  RequiredArguments({"expression"sv, "context"sv});
  DefineArgTypes({"expression", FieldType::String}, {"frameId", FieldType::Int}, {"context", FieldType::String});

  static EvaluationContext parse_context(std::string_view input) noexcept;
  static UICommand *PrepareEvaluateCommand(u64 seq, const nlohmann::json &args);
};

struct EvaluateResponse final : public UIResult
{
  EvaluateResponse(bool success, Evaluate *cmd, std::optional<int> variablesReference, std::pmr::string *result,
                   std::optional<std::string> &&type, std::optional<std::string> &&memoryReference) noexcept;
  ~EvaluateResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  std::pmr::string *result;
  std::optional<std::string> type;
  int variablesReference;
  std::optional<std::string> memoryReference;
};

struct Variables final : public UICommand
{
  Variables(u64 seq, VariableReferenceId var_ref, std::optional<u32> start, std::optional<u32> count) noexcept;
  ~Variables() override = default;
  UIResultPtr Execute() noexcept final;
  ErrorResponse *error(std::string &&msg) noexcept;
  VariableReferenceId mVariablesReferenceId;
  std::optional<u32> start;
  std::optional<u32> count;
  DEFINE_NAME("variables");
  RequiredArguments({"variablesReference"sv});
  DefineArgTypes({"variablesReference", FieldType::Int}, {"start", FieldType::Int}, {"count", FieldType::Int});
};

struct VariablesResponse final : public UIResult
{
  VariablesResponse(bool success, Variables *cmd, std::vector<Ref<sym::Value>> &&vars) noexcept;
  ~VariablesResponse() noexcept override;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  int requested_reference;
  std::vector<Ref<sym::Value>> variables;
};

struct DisassembleResponse final : public UIResult
{
  CTOR(DisassembleResponse);
  ~DisassembleResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::vector<sym::Disassembly> instructions;
};

struct Disassemble final : public UICommand
{
  Disassemble(u64 seq, std::optional<AddrPtr> address, int byte_offset, int ins_offset, int ins_count,
              bool resolve_symbols) noexcept;
  ~Disassemble() noexcept override = default;
  UIResultPtr Execute() noexcept final;

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

enum ScriptKind : u8
{
  Inline,
  File
};

struct ImportScript final : public UICommand
{
  DEFINE_NAME("importScript");
  ImportScript(u64 seq, std::string &&scriptSource) noexcept;
  ~ImportScript() noexcept override = default;
  UIResultPtr Execute() noexcept final;
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
struct ProcessId
{
  Pid mPid;
  u32 mDebugSessionId;
};

struct GetProcesses final : public UICommand
{
  using IdContainer = std::vector<ProcessId>;
  DEFINE_NAME("getProcesses");
  GetProcesses(u64 seq) noexcept : UICommand(seq) {}
  ~GetProcesses() noexcept override = default;
  UIResultPtr Execute() noexcept final;
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

struct InvalidArgsResponse final : public UIResult
{
  InvalidArgsResponse(std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  std::string_view command;
  MissingOrInvalidArgs missing_or_invalid;
};

template <typename T>
concept HasName = requires(T t) {
  { T::Request } -> std::convertible_to<std::string_view>;
};

struct InvalidArgs final : public UICommand
{
  InvalidArgs(u64 seq, std::string_view command, MissingOrInvalidArgs &&missing_args) noexcept;
  ~InvalidArgs() override = default;

  UIResultPtr Execute() noexcept final;

  ArgumentErrorKind kind;
  std::string_view command;
  MissingOrInvalidArgs missing_arguments;

  DEFINE_NAME("disassemble");
};

ui::UICommand *ParseDebugAdapterCommand(const DebugAdapterClient &client, std::string packet) noexcept;

template <typename Derived, typename JsonArgs>
static constexpr auto
Validate(uint64_t seq, const JsonArgs &args) -> InvalidArgs *
{
  if (auto &&missing = UICommand::CheckArguments<Derived>(args); missing) {
    return new ui::dap::InvalidArgs{seq, Derived::Request, std::move(missing.value())};
  } else {
    return nullptr;
  }
}
}; // namespace ui::dap
} // namespace mdb

namespace fmt {
template <> struct formatter<mdb::ui::dap::ProcessId> : Default<mdb::ui::dap::ProcessId>
{
  template <typename FormatContext>
  auto
  format(const mdb::ui::dap::ProcessId &processId, FormatContext &ctx) const
  {
    auto it = ctx.out();
    return fmt::format_to(it, R"({{ "pid": {}, "sessionId": {} }})", processId.mPid, processId.mDebugSessionId);
  }
};
} // namespace fmt