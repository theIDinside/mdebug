#pragma once

#include "dwarf_defs.h"
#include <fmt/core.h>

namespace fmt {
template <> struct fmt::formatter<Attribute>
{
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx);

  template <typename FormatContext> auto format(Attribute const &attribute, FormatContext &ctx);
};

template <> struct fmt::formatter<AttributeForm>
{
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx);

  template <typename FormatContext> auto format(AttributeForm const &form, FormatContext &ctx);
};

template <> struct fmt::formatter<DwarfTag>
{
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx);

  template <typename FormatContext> auto format(DwarfTag const &form, FormatContext &ctx);
};

template <typename ParseContext>
constexpr auto
fmt::formatter<Attribute>::parse(ParseContext &ctx)
{
  return ctx.begin();
}

template <typename FormatContext>
auto
fmt::formatter<Attribute>::format(Attribute const &attribute, FormatContext &ctx)
{
  return fmt::format_to(ctx.out(), "{}", to_str(attribute));
}

template <typename ParseContext>
constexpr auto
fmt::formatter<AttributeForm>::parse(ParseContext &ctx)
{
  return ctx.begin();
}

template <typename FormatContext>
auto
fmt::formatter<AttributeForm>::format(AttributeForm const &form, FormatContext &ctx)
{
  return fmt::format_to(ctx.out(), "{}", to_str(form));
}

template <typename ParseContext>
constexpr auto
fmt::formatter<DwarfTag>::parse(ParseContext &ctx)
{
  return ctx.begin();
}

template <typename FormatContext>
auto
fmt::formatter<DwarfTag>::format(DwarfTag const &tag, FormatContext &ctx)
{
  return fmt::format_to(ctx.out(), "{}", to_str(tag));
}

} // namespace fmt