/** LICENSE TEMPLATE */
#pragma once

// system
#include <format>
#include <string_view>

template <typename C> struct JoinFormatIterator
{
  const C &mContainer;
  std::string_view mDelimiter = ",";
};

template <typename C> struct HexJoinFormatIterator
{
  const C &mContainer;
  std::string_view mDelimiter = ",";
};

template <typename C> using Join = JoinFormatIterator<C>;

template <typename C> struct std::formatter<HexJoinFormatIterator<C>>
{
  using SelfType = HexJoinFormatIterator<C>;
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const SelfType &self, FormatContext &ctx) const
  {
    auto out = ctx.out();
    const auto *ptr = self.mContainer.data();

    if (self.mContainer.empty()) {
      return out;
    }

    const auto size = self.mContainer.size();

    if (size == 1) {
      return std::format_to(out, "{:x}", *ptr);
    }

    for (auto i = 0; i < size - 1; ++i) {
      out = std::format_to(out, "{:x}", ptr[i]);
      for (const auto &ch : self.mDelimiter) {
        *out++ = ch;
      }
    }

    return std::format_to(out, "{:x}", ptr[self.mContainer.size() - 1]);
  }
};

struct EscapeFormatter
{
  std::string_view mString;
};

template <typename OutIter>
constexpr OutIter
FormatEscaped(OutIter it, std::string_view string) noexcept
{
  for (auto ch : string) {
    switch (ch) {
    case '\n':
      *it++ = '\\';
      *it++ = 'n';
      break;
    case '\r':
      *it++ = '\\';
      *it++ = 'r';
      break;
    case '\t':
      *it++ = '\\';
      *it++ = 't';
      break;
    case '"':
      *it++ = '\\';
      *it++ = '"';
      break;
    default:
      *it++ = ch;
    }
  }
  return it;
}

template <> struct std::formatter<EscapeFormatter>
{
  constexpr auto
  parse(auto &ctx)
  {
    return ctx.begin();
  }

  auto
  format(const auto &self, auto &ctx) const noexcept
  {
    return FormatEscaped(ctx.out(), self.mString);
  }
};

template <typename C> struct std::formatter<JoinFormatIterator<C>>
{
  using SelfType = JoinFormatIterator<C>;
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const SelfType &self, FormatContext &ctx) const
  {
    auto out = ctx.out();
    const auto *ptr = self.mContainer.data();

    if (self.mContainer.empty()) {
      return out;
    }

    const auto size = self.mContainer.size();

    if (size == 1) {
      return std::format_to(out, "{}", *ptr);
    }

    for (auto i = 0; i < size - 1; ++i) {
      out = std::format_to(out, "{}", ptr[i]);
      for (const auto &ch : self.mDelimiter) {
        *out++ = ch;
      }
    }

    return std::format_to(out, "{}", ptr[self.mContainer.size() - 1]);
  }
};