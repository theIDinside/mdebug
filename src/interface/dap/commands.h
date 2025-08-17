/** LICENSE TEMPLATE */
#pragma once

// mdb
// #include <bp.h>
#include <bp_defs.h>
#include <common/typedefs.h>
#include <interface/attach_args.h>
#include <interface/dap/interface.h>
#include <interface/dap/invalid.h>
#include <interface/dap/types.h>
#include <interface/ui_command.h>
#include <interface/ui_result.h>
#include <json/json.h>
#include <lib/arena_allocator.h>
#include <symbolication/disassemble.h>
#include <utils/format_utils.h>

// stdlib
#include <cctype>
#include <memory_resource>
#include <span>

namespace mdb {

using namespace std::string_view_literals;
enum class BreakpointType : std::uint8_t;

namespace ui::dap {

struct Breakpoint;

using namespace std::string_view_literals;

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
  std::string_view err_msg{ "" };
  std::array<std::string_view, CurrentEnumMax> enum_values{};
  u8 enum_variants{ 0 };

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

  consteval VerifyField(
    std::string_view fieldName, FieldType fieldType, std::array<std::string_view, CurrentEnumMax> enumerations)
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

  template <typename JsonValueType>
  constexpr VerifyResult
  isOK(const JsonValueType &j, std::string_view fieldName) const noexcept
  {
    if (const auto it =
          std::find_if(fields.cbegin(), fields.cend(), [&](const auto &f) { return fieldName == f.name; });
      it != std::cend(fields)) {
      switch (it->type) {
      case FieldType::Address:
        if (!j.IsString()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredStringType(), fieldName) };
        } else {
          std::string_view s = j.UncheckedGetStringView();
          if (s.starts_with("0x")) {
            s.remove_prefix(2);
          }
          for (auto ch : s) {
            if (!std::isxdigit(ch)) {
              return VerifyResult{ std::make_pair(ArgumentError::RequiredAddressType(), fieldName) };
            }
          }
          return VerifyResult{ std::nullopt };
        }
      case FieldType::String:
        if (!j.IsString()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredStringType(), fieldName) };
        }
        break;
      case FieldType::Float:
        [[fallthrough]];
      case FieldType::Int:
        if (!j.IsNumber()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredNumberType(), fieldName) };
        }
        break;
      case FieldType::Boolean:
        if (!j.IsBoolean()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredBooleanType(), fieldName) };
        }
        break;
      case FieldType::Enumeration: {
        if (!j.IsString()) {
          return VerifyResult{ std::make_pair(
            ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
              .description = "Config enumeration values must be of string type" },
            fieldName) };
        }
        std::string_view value = j.UncheckedGetStringView();
        if (!it->has_enum_variant(value)) {
          return VerifyResult{ std::make_pair(
            ArgumentError{ .kind = ArgumentErrorKind::InvalidInput,
              .description = std::format(
                "Invalid variant: '{}'. Valid: {}", value, JoinFormatIterator{ it->get_enum_values(), "|" }) },
            fieldName) };
        }
        break;
      }
      case FieldType::Array:
        if (!j.IsArray()) {
          return VerifyResult{ std::make_pair(ArgumentError::RequiredArrayType(), fieldName) };
        }
        break;
      }
      return VerifyResult{ std::nullopt };
    } else {
      return VerifyResult{ std::nullopt };
    }
  }
};

#define DefineArgTypes(...)                                                                                       \
  static constexpr auto ArgsFieldsArray = std::to_array<VerifyField>({ __VA_ARGS__ });                            \
  static constexpr VerifyMap<ArgsFieldsArray.size()> ArgTypes{ ArgsFieldsArray };                                 \
  template <typename Json>                                                                                        \
  constexpr static auto ValidateArg(std::string_view argName, const Json &argContents) noexcept                   \
    -> std::optional<InvalidArg>                                                                                  \
  {                                                                                                               \
    if (auto err = ArgTypes.isOK(argContents, argName); err) {                                                    \
      return std::move(err).take();                                                                               \
    }                                                                                                             \
    return std::nullopt;                                                                                          \
  }

struct Message
{
  std::string format;
  std::unordered_map<std::string, std::string> variables{};
  bool show_user{ true };
  std::optional<int> id{};
};

struct ErrorResponse final : ui::UIResult
{
  ErrorResponse(std::string_view command,
    ui::UICommandPtr cmd,
    std::optional<std::string> &&short_message,
    std::optional<Message> &&message) noexcept;
  ~ErrorResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  SessionId mPid;
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
  ReverseContinue(UICommandArg arg, int thread_id) noexcept;
  ~ReverseContinue() noexcept override = default;
  int thread_id;
  UIResultPtr Execute() noexcept final;

  DEFINE_NAME("reverseContinue");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
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

  Continue(UICommandArg arg, int tid, bool all) noexcept
      : UICommand(std::move(arg)), thread_id(tid), continue_all(all)
  {
  }
  ~Continue() override = default;
  UIResultPtr Execute() noexcept final;

  DEFINE_NAME("continue");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int }, { "sessionId", FieldType::Int });
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

  Pause(UICommandArg arg, Args args) noexcept : UICommand(std::move(arg)), pauseArgs(args) {}
  ~Pause() override = default;
  UIResultPtr Execute() noexcept final;

  Args pauseArgs;
  DEFINE_NAME("pause");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
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

  Next(UICommandArg arg, int tid, bool all, SteppingGranularity granularity) noexcept
      : UICommand(std::move(arg)), thread_id(tid), continue_all(all), granularity(granularity)
  {
  }
  ~Next() override = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("next");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

struct StepBackResponse final : ui::UIResult
{
  enum class Result
  {
    Success,
    NotStopped,
    NotReplaySession
  };
  StepBackResponse(Result result, UICommandPtr cmd) noexcept
      : UIResult(result == Result::Success, cmd), mResult(result) {};
  ~StepBackResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;

  Result mResult;
};

struct StepBack final : public ui::UICommand
{
  int thread_id;

  StepBack(UICommandArg arg, int tid, bool all) noexcept : UICommand(std::move(arg)), thread_id(tid) {}
  ~StepBack() override = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("stepBack");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
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

  StepIn(UICommandArg arg, int thread_id, bool singleThread, SteppingGranularity granularity) noexcept
      : UICommand(std::move(arg)), thread_id(thread_id), singleThread(singleThread), granularity(granularity)
  {
  }

  ~StepIn() noexcept final = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("stepIn");
  RequiredArguments({ "threadId" });
  DefineArgTypes({ "threadId", FieldType::Int });
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

  StepOut(UICommandArg arg, int tid, bool all) noexcept
      : UICommand(std::move(arg)), thread_id(tid), continue_all(all)
  {
  }
  ~StepOut() override = default;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("stepOut");
  RequiredArguments({ "threadId"sv });
  DefineArgTypes({ "threadId", FieldType::Int });
};

// This response looks the same for all breakpoints, InstructionBreakpoint, FunctionBreakpoint and SourceBreakpoint
// in the DAP spec
struct SetBreakpointsResponse final : ui::UIResult
{
  SetBreakpointsResponse(bool success, ui::UICommandPtr cmd, BreakpointRequestKind type) noexcept;
  std::vector<ui::dap::Breakpoint> mBreakpoints{};
  BreakpointRequestKind mType;
  ~SetBreakpointsResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  void AddBreakpoint(Breakpoint &&bp) noexcept;
};

struct SetBreakpoints final : public ui::UICommand
{
  SetBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept;
  ~SetBreakpoints() override = default;
  mdbjson::JsonValue args;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("setBreakpoints");
  RequiredArguments({ "source"sv });
};

struct SetExceptionBreakpoints final : public ui::UICommand
{
  SetExceptionBreakpoints(UICommandArg arguence, const mdbjson::JsonValue &args) noexcept;
  ~SetExceptionBreakpoints() override = default;
  UIResultPtr Execute() noexcept final;

  mdbjson::JsonValue args;

  DEFINE_NAME("setExceptionBreakpoints");
  RequiredArguments({ "filters"sv });
  DefineArgTypes({ "filters", FieldType::Array });
};

struct SetInstructionBreakpoints final : public ui::UICommand
{
  SetInstructionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept;
  ~SetInstructionBreakpoints() override = default;
  mdbjson::JsonValue args;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("setInstructionBreakpoints");
  RequiredArguments({ "breakpoints"sv });
};

struct SetFunctionBreakpoints final : public ui::UICommand
{
  SetFunctionBreakpoints(UICommandArg arg, const mdbjson::JsonValue &arguments) noexcept;
  ~SetFunctionBreakpoints() override = default;
  mdbjson::JsonValue args;
  UIResultPtr Execute() noexcept final;
  DEFINE_NAME("setFunctionBreakpoints");
  RequiredArguments({ "breakpoints"sv });
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
  WriteMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset, std::vector<u8> &&bytes) noexcept;
  ~WriteMemory() override = default;
  UIResultPtr Execute() noexcept final;

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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  AddrPtr first_readable_address;
  u64 unreadable_bytes;
  std::pmr::string data_base64;
};

struct ReadMemory final : public ui::UICommand
{
  ReadMemory(UICommandArg arg, std::optional<AddrPtr> address, int offset, u64 bytes) noexcept;
  ~ReadMemory() override = default;
  UIResultPtr Execute() noexcept final;

  std::optional<AddrPtr> address;
  int offset;
  u64 bytes;

  DEFINE_NAME("readMemory");
  RequiredArguments({ "memoryReference"sv, "count"sv });
  DefineArgTypes(
    { "memoryReference", FieldType::Address }, { "count", FieldType::Int }, { "offset", FieldType::Int });
};

struct ConfigurationDoneResponse final : public ui::UIResult
{
  CTOR(ConfigurationDoneResponse);
  ~ConfigurationDoneResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct ConfigurationDone final : public ui::UICommand
{
  ConfigurationDone(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}

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
  std::string mSessionId;
  bool RRSession;
};

struct Initialize final : public ui::UICommand
{
  Initialize(UICommandArg arg, mdbjson::JsonValue arguments) noexcept;
  ~Initialize() override = default;
  UIResultPtr Execute() noexcept final;
  mdbjson::JsonValue args;
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
  Disconnect(UICommandArg arg, bool restart, bool terminateTracee, bool suspendTracee) noexcept;
  ~Disconnect() override = default;
  UIResultPtr Execute() noexcept final;
  bool restart, mTerminateTracee, mSuspendTracee;
  DEFINE_NAME("disconnect");
  NoRequiredArgs();
};

struct LaunchResponse final : public UIResult
{
  LaunchResponse(SessionId sessionId, std::optional<SessionId> newProcess, bool success, UICommandPtr cmd) noexcept
      : UIResult{ success, cmd }, mProcessId{ newProcess }, mRequestingSessionId{ sessionId } {};
  ~LaunchResponse() noexcept override;
  std::optional<SessionId> mProcessId;
  SessionId mRequestingSessionId;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Launch final : public UICommand
{
  Launch(UICommandArg arg,
    SessionId id,
    bool stopAtEntry,
    Path program,
    std::pmr::vector<std::pmr::string> &&program_args,
    std::optional<BreakpointBehavior> breakpointBehavior) noexcept;
  ~Launch() override = default;
  UIResultPtr Execute() noexcept final;
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
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Attach final : public UICommand
{
  Attach(UICommandArg arg, SessionId sessionId, AttachArgs args) noexcept;
  ~Attach() override = default;
  UIResultPtr Execute() noexcept final;

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

  static ui::UICommand *create(UICommandArg arg, const mdbjson::JsonValue &args) noexcept;
};

struct TerminateResponse final : public UIResult
{
  CTOR(TerminateResponse);
  ~TerminateResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
};

struct Terminate final : public UICommand
{
  Terminate(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
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
  Threads(UICommandArg arg) noexcept : UICommand(std::move(arg)) {}
  ~Threads() override = default;
  UIResultPtr Execute() noexcept final;
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

struct Scopes final : public UICommand
{
  Scopes(UICommandArg arg, int frameId) noexcept;
  ~Scopes() override = default;
  UIResultPtr Execute() noexcept final;
  int mFrameId;
  DEFINE_NAME("scopes");
  RequiredArguments({ "frameId"sv });
  DefineArgTypes({ "frameId", FieldType::Int });
};

struct ScopesResponse final : public UIResult
{
  ScopesResponse(bool success, Scopes *cmd, std::array<Scope, 3> scopes) noexcept;
  ~ScopesResponse() noexcept override = default;
  std::pmr::string Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept final;
  // For now, we only have 3 scopes, Args, Locals, Registers
  std::array<Scope, 3> scopes;
};

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

template <typename T>
concept HasName = requires(T t) {
  { T::Request } -> std::convertible_to<std::string_view>;
};

ui::UICommand *ParseDebugAdapterCommand(DebugAdapterClient &client, std::string_view packet) noexcept;

}; // namespace ui::dap
} // namespace mdb
