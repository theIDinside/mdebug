#pragma once
#include "symbolication/dwarf/lnp.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/type.h"
#include <common.h>
#include <symbolication/fnsymbol.h>

namespace ui::dap {
struct Scope;
}

namespace sym {
enum class FrameType : u8
{
  Full,
  ElfSymbol,
  Unknown
};

enum class InsideRange
{
  Yes,
  No,
  Unknown
};

enum class VariableSet
{
  Arguments,
  Locals,
  Static,
  Global
};

enum class FrameVariableKind
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

public:
  Immutable<NonNullPtr<TaskInfo>> task;

  template <typename T>
  explicit Frame(TaskInfo &task, u32 level, int frame_id, AddrPtr pc, T sym_info) noexcept
      : rip(pc), lvl(level), frame_id(frame_id), task(NonNull(task))
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
    if (l.type != r.type)
      return false;

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

struct CallStack
{
  NO_COPY(CallStack);
  explicit CallStack(Tid tid) noexcept;
  ~CallStack() = default;

  Frame *get_frame(int frame_id) noexcept;

  Tid tid; // the task associated with this call stack
  bool dirty;
  std::vector<Frame> frames; // the call stack
  std::vector<AddrPtr> pcs;
  std::vector<std::array<u64, 17>> reg_unwind_buffer;
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
  format(const sym::Frame &frame, FormatContext &ctx)
  {

    return fmt::format_to(ctx.out(), "{{ pc: {}, level: {}, fn: {} }}", frame.pc(), frame.level(),
                          frame.function_name().value_or("Unknown"));
  }
};
} // namespace fmt