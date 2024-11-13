#pragma once
#include "interface/dap/types.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/type.h"
#include <common.h>
#include <symbolication/fnsymbol.h>

class SymbolFile;
struct CallStackRequest;
struct TaskInfo;
namespace ui::dap {
struct Scope;
}

namespace sym {
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
  AddrPtr rip = nullptr;
  union
  {
    sym::FunctionSymbol *full_symbol;
    const MinSymbol *min_symbol;
    std::nullptr_t null;
  } symbol = {nullptr};

  u32 lvl = -1;
  FrameType type = FrameType::Unknown;
  u32 frame_id = -1;
  SymbolFile *symbol_file;
  std::array<ui::dap::Scope, 3> cached_scopes{};

public:
  Immutable<NonNullPtr<TaskInfo>> task;

  template <typename T>
  explicit Frame(SymbolFile *symbol_file, TaskInfo &task, u32 level, u32 frame_id, AddrPtr pc, T sym_info) noexcept
      : rip(pc), lvl(level), frame_id(frame_id), symbol_file(symbol_file), task(NonNull(task))
  {
    using Type = std::remove_pointer_t<std::remove_const_t<T>>;
    static_assert(std::is_pointer_v<T> || std::is_same_v<T, std::nullptr_t>,
                  "Frame expects either FunctionSymbol or MinSymbol pointers (or a nullptr)");
    if constexpr (std::is_same_v<Type, sym::FunctionSymbol> || std::is_same_v<Type, const sym::FunctionSymbol>) {
      type = FrameType::Full;
      symbol.full_symbol = sym_info;
      ASSERT(symbol.full_symbol != nullptr, "Setting to nullptr when expecting full symbol information to exist.");
    } else if constexpr (std::is_same_v<Type, MinSymbol> || std::is_same_v<Type, const MinSymbol>) {
      type = FrameType::ElfSymbol;
      symbol.min_symbol = sym_info;
      ASSERT(symbol.min_symbol != nullptr, "Setting to nullptr when expecting ELF symbol information to exist.");
    } else if constexpr (std::is_null_pointer_v<T>) {
      type = FrameType::Unknown;
      symbol.null = std::nullptr_t{};
    } else {
      static_assert(always_false<T>, "Could not determine symbol type!");
    }
  }

  Frame(const Frame &) = default;
  Frame &operator=(const Frame &) = default;
  Frame(Frame &&) = default;
  Frame &operator=(Frame &&) = default;

  InsideRange inside(TPtr<void> addr) const noexcept;
  std::optional<std::string_view> name() const noexcept;
  // checks if this Frame has symbol info, whether that be of type Full or Elf
  bool has_symbol_info() const noexcept;
  FrameType frame_type() const noexcept;
  int id() const noexcept;
  int level() const noexcept;
  AddrPtr pc() const noexcept;
  SymbolFile *get_symbol_file() noexcept;

  const sym::FunctionSymbol &full_symbol_info() const noexcept;

  sym::FunctionSymbol *maybe_get_full_symbols() const noexcept;
  const MinSymbol *maybe_get_min_symbols() const noexcept;

  IterateFrameSymbols block_symbol_iterator(FrameVariableKind variable_set) noexcept;
  u32 frame_locals_count() const noexcept;
  u32 frame_args_count() const noexcept;

  friend constexpr bool
  operator==(const Frame &l, const Frame &r) noexcept
  {
    return compare_eq(l, r);
  }

  friend constexpr bool
  same_symbol(const Frame &l, const Frame &r) noexcept
  {
    return l == r;
  }

  friend constexpr AddrPtr resume_address(const Frame &f) noexcept;

  friend constexpr bool
  compare_eq(const Frame &l, const Frame &r) noexcept
  {
    if (l.type != r.type) {
      return false;
    }

    switch (l.type) {
    case FrameType::Full:
      return sym::is_same(l.symbol.full_symbol, r.symbol.full_symbol);
    case FrameType::ElfSymbol:
      return l.symbol.min_symbol == r.symbol.min_symbol;
    case FrameType::Unknown:
      return false;
    }
    return false;
  }

  std::optional<std::string_view> function_name() const noexcept;

  /**
   * Return the line table for the compilation unit where this Frame exists in.
   */
  std::optional<dw::LineTable> cu_line_table() const noexcept;
  std::array<ui::dap::Scope, 3> scopes() noexcept;
  std::optional<ui::dap::Scope> scope(u32 var_ref) noexcept;
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
      return BlockSymbolIterator::Begin(&frame.full_symbol_info().get_args(), 1);
      break;
    case FrameVariableKind::Locals:
      return BlockSymbolIterator::Begin(frame.full_symbol_info().get_frame_locals());
      break;
    }
    NEVER("Unknown frame variables kind");
  }

  BlockSymbolIterator
  end() noexcept
  {
    switch (type) {
    case FrameVariableKind::Arguments:
      return BlockSymbolIterator::End(&frame.full_symbol_info().get_args(), 1);
      break;
    case FrameVariableKind::Locals:
      return BlockSymbolIterator::End(frame.full_symbol_info().get_frame_locals());
      break;
    }
    NEVER("Unknown frame variables kind");
  }

private:
  Frame &frame;
  FrameVariableKind type;
};

constexpr AddrPtr
resume_address(const Frame &f) noexcept
{
  return f.rip;
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

private:
  static constexpr auto X86_64_RIP_REGISTER = 16;
};

class CallStack
{
public:
  NO_COPY(CallStack);
  explicit CallStack(TraceeController *supervisor, TaskInfo *task) noexcept;
  ~CallStack() = default;

  Frame *get_frame(int frame_id) noexcept;
  Frame *GetFrameAtLevel(u32 level) noexcept;
  u64 unwind_buffer_register(u8 level, u16 register_number) noexcept;

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
    frames.push_back(sym::Frame{args...});
  }

private:
  void ClearFrames() noexcept;
  void ClearProgramCounters() noexcept;
  void ClearUnwoundRegisters() noexcept;
  AddrPtr GetTopMostPc() const noexcept;
  bool ResolveNewFrameRegisters(CFAStateMachine &stateMachine) noexcept;

  TaskInfo *mTask; // the task associated with this call stack
  TraceeController *mSupervisor;
  bool dirty;
  std::vector<Frame> frames{}; // the call stack
  std::vector<AddrPtr> mFrameProgramCounters{};
  std::vector<FrameUnwindState> mUnwoundRegister{};
};
} // namespace sym

namespace fmt {
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
    return fmt::format_to(ctx.out(), "{{ pc: {}, level: {}, fn: {} }}", frame.pc(), frame.level(),
                          frame.function_name().value_or("Unknown"));
  }
};
} // namespace fmt