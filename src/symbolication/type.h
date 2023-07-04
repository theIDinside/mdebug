#pragma once
#include "../common.h"
#include "block.h"
#include <optional>

struct Field
{
  const char *name;
  u32 offset;
  u32 size;
};

struct Type
{
  const char *name;
  std::vector<Field> members;
  u64 size_of() const noexcept;
};

struct Symbol
{
  const char *name;
  Type type;
  TPtr<void> address;
};

struct File
{
  std::string_view name;
  std::vector<Block> blocks;
  Path dir() const noexcept;
};

namespace fmt {
template <> struct formatter<File>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(File const &f, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{{ path: {}, low: {}, high: {}, blocks: {} }}", f.name, f.blocks.front().low,
                          f.blocks.back().high, f.blocks.size());
  }
};

} // namespace fmt