#pragma once
#include "symbolication/elf_symbols.h"
#include <common.h>
#include <cstddef>
#include <symbolication/fnsymbol.h>
#include <type_traits>

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

class Frame
{
private:
  AddrPtr rip = nullptr;
  union
  {
    const sym::FunctionSymbol *full_symbol;
    const MinSymbol *min_symbol;
    std::nullptr_t null;
  } symbol = {nullptr};

  int lvl = -1;
  FrameType type = FrameType::Unknown;
  int frame_id = -1;

public:
  template <typename T>
  explicit Frame(int level, int frame_id, AddrPtr pc, T sym_info) noexcept
      : rip(pc), lvl(level), frame_id(frame_id)
  {
    using Type = std::remove_pointer_t<std::remove_const_t<T>>;
    static_assert(std::is_pointer_v<T> || std::is_same_v<T, std::nullptr_t>,
                  "Frame expects either FunctionSymbol or MinSymbol pointers (or a nullptr)");
    if constexpr (std::is_same_v<Type, sym::FunctionSymbol> || std::is_same_v<Type, const sym::FunctionSymbol>) {
      type = FrameType::Full;
      symbol.full_symbol = sym_info;
    } else if constexpr (std::is_same_v<Type, MinSymbol> || std::is_same_v<Type, const MinSymbol>) {
      type = FrameType::ElfSymbol;
      symbol.min_symbol = sym_info;
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
  const sym::FunctionSymbol *full_symbol_info() const noexcept;
  const MinSymbol *min_symbol_info() const noexcept;

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

  const Frame *get_frame(int frame_id) const noexcept;

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