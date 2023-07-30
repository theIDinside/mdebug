#pragma once
#include "../common.h"
#include "type.h"
#include <vector>

namespace sym {
enum class FrameType : u8
{
  Full,
  Unknown
};

enum class InsideRange
{
  Yes,
  No,
  Unknown
};

struct Frame
{
  InsideRange inside(TPtr<void> addr) const noexcept;
  std::optional<std::string_view> name() const noexcept;
  AddrPtr rip;
  const FunctionSymbol *symbol;
  const CompilationUnitFile *cu_file;
  int level;
  FrameType type;

  friend constexpr bool
  operator==(const Frame &l, const Frame &r) noexcept
  {
    return l.level == r.level && l.cu_file == r.cu_file && l.symbol == r.symbol;
  }

  friend constexpr bool
  same_symbol(const Frame &l, const Frame &r) noexcept
  {
    return l.symbol == r.symbol && l.cu_file == r.cu_file;
  }

  friend constexpr AddrPtr resume_address(const Frame &f) noexcept;

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

  Tid tid;                   // the task associated with this call stack
  std::vector<Frame> frames; // the call stack
  std::vector<AddrPtr> pcs;
  std::optional<int> has_frame(const Frame &f) const noexcept;
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

    return fmt::format_to(ctx.out(), "{{ pc: {}, level: {}, fn: {} }}", frame.rip, frame.level,
                          frame.function_name().value_or("Unknown"));
  }
};
} // namespace fmt