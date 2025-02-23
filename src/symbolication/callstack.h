/** LICENSE TEMPLATE */
#pragma once
#include "interface/dap/types.h"
// #include "symbolication/dwarf/lnp.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/type.h"
#include "symbolication/variable_reference.h"
#include "utils/immutable.h"
#include <common.h>
#include <symbolication/fnsymbol.h>

namespace mdb {
class SymbolFile;
struct CallStackRequest;
class TaskInfo;
namespace ui::dap {
struct Scope;
}
namespace sym {
namespace dw {
class SourceCodeFile;
struct LineTableEntry;
} // namespace dw

class CFAStateMachine;

enum class FrameType : u8
{
  Full,
  ElfSymbol,
  Unknown
};

enum class InsideRange : u8
{
  Yes,
  No,
  Unknown
};

enum class VariableSet : u8
{
  Arguments,
  Locals,
  Static,
  Global
};

enum class FrameVariableKind : u8
{
  Arguments,
  Locals
};

class IterateFrameSymbols;

class Frame
{
private:
  AddrPtr mFramePc = nullptr;
  union
  {
    sym::FunctionSymbol *uFullSymbol;
    const MinSymbol *uMinSymbol;
    std::nullptr_t uNull;
  } mSymbolUnion = {nullptr};

  u32 mFrameLevel = -1;
  FrameType mFrameType = FrameType::Unknown;
  VariableReferenceId mFrameId = -1;
  SymbolFile *mOwningSymbolFile;
  std::array<ui::dap::Scope, 3> mFrameScopes{};

public:
  Immutable<NonNullPtr<TaskInfo>> mTask;

  template <typename T>
  explicit Frame(SymbolFile *symbol_file, TaskInfo &task, u32 level, VariableReferenceId frame_id, AddrPtr pc,
                 T sym_info) noexcept
      : mFramePc(pc), mFrameLevel(level), mFrameId(frame_id), mOwningSymbolFile(symbol_file), mTask(NonNull(task))
  {
    using Type = std::remove_pointer_t<std::remove_const_t<T>>;
    static_assert(std::is_pointer_v<T> || std::is_same_v<T, std::nullptr_t>,
                  "Frame expects either FunctionSymbol or MinSymbol pointers (or a nullptr)");
    if constexpr (std::is_same_v<Type, sym::FunctionSymbol> || std::is_same_v<Type, const sym::FunctionSymbol>) {
      mFrameType = FrameType::Full;
      mSymbolUnion.uFullSymbol = sym_info;
      ASSERT(mSymbolUnion.uFullSymbol != nullptr,
             "Setting to nullptr when expecting full symbol information to exist.");
    } else if constexpr (std::is_same_v<Type, MinSymbol> || std::is_same_v<Type, const MinSymbol>) {
      mFrameType = FrameType::ElfSymbol;
      mSymbolUnion.uMinSymbol = sym_info;
      ASSERT(mSymbolUnion.uMinSymbol != nullptr,
             "Setting to nullptr when expecting ELF symbol information to exist.");
    } else if constexpr (std::is_null_pointer_v<T>) {
      mFrameType = FrameType::Unknown;
      mSymbolUnion.uNull = std::nullptr_t{};
    } else {
      static_assert(always_false<T>, "Could not determine symbol type!");
    }
  }

  Frame(const Frame &) = default;
  Frame &operator=(const Frame &) = default;
  Frame(Frame &&) = default;
  Frame &operator=(Frame &&) = default;

  InsideRange IsInside(TPtr<void> addr) const noexcept;
  std::optional<std::string_view> Name() const noexcept;
  std::optional<const char *> CStringName() const noexcept;
  // checks if this Frame has symbol info, whether that be of type Full or Elf
  bool HasSymbolInfo() const noexcept;
  FrameType GetFrameType() const noexcept;
  VariableReferenceId FrameId() const noexcept;
  int FrameLevel() const noexcept;
  AddrPtr FramePc() const noexcept;
  SymbolFile *GetSymbolFile() const noexcept;
  TaskInfo *Task() const noexcept;

  sym::FunctionSymbol &FullSymbolInfo() noexcept;

  sym::FunctionSymbol *MaybeGetFullSymbolInfo() const noexcept;
  const MinSymbol *MaybeGetMinimalSymbol() const noexcept;

  IterateFrameSymbols BlockSymbolIterator(FrameVariableKind variable_set) noexcept;

  u32 GetInitializedVariables(FrameVariableKind variableSet,
                              std::vector<NonNullPtr<const sym::Symbol>> &outVector) noexcept;

  u32 FrameLocalVariablesCount() noexcept;
  u32 FrameParameterCounts() noexcept;

  friend constexpr bool
  operator==(const Frame &l, const Frame &r) noexcept
  {
    return CompareEquals(l, r);
  }

  friend constexpr bool
  SameSymbol(const Frame &l, const Frame &r) noexcept
  {
    return l == r;
  }

  friend constexpr AddrPtr ResumeAddress(const Frame &f) noexcept;

  friend constexpr bool
  CompareEquals(const Frame &l, const Frame &r) noexcept
  {
    if (l.mFrameType != r.mFrameType) {
      return false;
    }

    switch (l.mFrameType) {
    case FrameType::Full:
      return sym::IsSame(l.mSymbolUnion.uFullSymbol, r.mSymbolUnion.uFullSymbol);
    case FrameType::ElfSymbol:
      return l.mSymbolUnion.uMinSymbol == r.mSymbolUnion.uMinSymbol;
    case FrameType::Unknown:
      return false;
    }
    return false;
  }

  std::pair<dw::SourceCodeFile *, const dw::LineTableEntry *> GetLineTableEntry() noexcept;
  std::optional<std::string_view> GetFunctionName() const noexcept;
  std::array<ui::dap::Scope, 3> Scopes() noexcept;
  std::optional<ui::dap::Scope> Scope(u32 var_ref) noexcept;
};

class IterateFrameSymbols
{
public:
  IterateFrameSymbols(Frame &frame, FrameVariableKind type) noexcept : frame(frame), type(type) {}

  BlockSymbolIterator
  begin() noexcept
  {
    switch (type) {
    case FrameVariableKind::Arguments:
      return BlockSymbolIterator::Begin(&frame.FullSymbolInfo().GetFunctionArguments(), 1);
      break;
    case FrameVariableKind::Locals:
      return BlockSymbolIterator::Begin(frame.FullSymbolInfo().GetFrameLocalVariableBlocks());
      break;
    }
    NEVER("Unknown frame variables kind");
  }

  BlockSymbolIterator
  end() noexcept
  {
    switch (type) {
    case FrameVariableKind::Arguments:
      return BlockSymbolIterator::End(&frame.FullSymbolInfo().GetFunctionArguments(), 1);
      break;
    case FrameVariableKind::Locals:
      return BlockSymbolIterator::End(frame.FullSymbolInfo().GetFrameLocalVariableBlocks());
      break;
    }
    NEVER("Unknown frame variables kind");
  }

private:
  Frame &frame;
  FrameVariableKind type;
};

constexpr AddrPtr
ResumeAddress(const Frame &f) noexcept
{
  return f.mFramePc;
}

class FrameUnwindState
{
  u64 mCanonicalFrameAddress;
  std::vector<u64> mFrameRegisters;

public:
  void SetCanonicalFrameAddress(u64 addr) noexcept;
  u64 CanonicalFrameAddress() const noexcept;
  void Reserve(u32 count) noexcept;
  u64 RegisterCount() const noexcept;
  void Set(u32 number, u64 value) noexcept;
  void Reset() noexcept;
  AddrPtr GetPc() const noexcept;
  AddrPtr GetRegister(u64 registerNumber) const noexcept;
  FrameUnwindState Clone() const noexcept;
};

class CallStack
{
  enum class CallStackState
  {
    Invalidated,
    Partial,
    Full,
  };

public:
  NO_COPY(CallStack);
  explicit CallStack(TraceeController *supervisor, TaskInfo *task) noexcept;
  ~CallStack() = default;

  Frame *GetFrame(u64 frameId) noexcept;
  Frame *GetFrameAtLevel(u32 level) noexcept;
  u64 UnwindRegister(u8 level, u16 register_number) noexcept;

  bool IsDirty() const noexcept;
  void SetDirty() noexcept;
  void Initialize() noexcept;
  void Reset() noexcept;
  void Reserve(u32 count) noexcept;

  u32 FramesCount() const noexcept;
  std::span<Frame> GetFrames() noexcept;
  std::optional<Frame> FindFrame(const Frame &frame) const noexcept;
  void Unwind(const CallStackRequest &req);
  FrameUnwindState *GetUnwindState(u32 level) noexcept;

  template <class Self>
  std::span<const AddrPtr>
  ReturnAddresses(this Self &&self) noexcept
  {
    return self.mFrameProgramCounters;
  }

  template <typename... Args>
  void
  PushFrame(Args &&...args)
  {
    mStackFrames.push_back(sym::Frame{args...});
  }

private:
  void ClearFrames() noexcept;
  void ClearProgramCounters() noexcept;
  void ClearUnwoundRegisters() noexcept;
  AddrPtr GetTopMostPc() const noexcept;
  bool ResolveNewFrameRegisters(CFAStateMachine &stateMachine) noexcept;
  // Any unwind operation consists of the new set of registers for a frame, that are derived from the newer set of
  // registers from a newer frame. As such, for an unwind operation for a frame, 2 frames are always important.
  std::pair<FrameUnwindState *, FrameUnwindState *> GetCurrent() noexcept;

  TaskInfo *mTask; // the task associated with this call stack
  TraceeController *mSupervisor;
  CallStackState mCallstackState{CallStackState::Invalidated};
  std::vector<Frame> mStackFrames{}; // the call stack
  std::vector<AddrPtr> mFrameProgramCounters{};
  std::vector<FrameUnwindState> mUnwoundRegister{};
};
} // namespace sym
} // namespace mdb
namespace fmt {
namespace sym = mdb::sym;
template <> struct formatter<sym::Frame>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::Frame &frame, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "{{ pc: {}, level: {}, fn: {} }}", frame.FramePc(), frame.FrameLevel(),
                          frame.GetFunctionName().value_or("Unknown"));
  }
};
} // namespace fmt