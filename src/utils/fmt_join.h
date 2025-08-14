/** LICENSE TEMPLATE */
#pragma once

// system
#include <format>
#include <span>
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
    // const std::span span{ self.mContainer };
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
    // const std::span span{ self.mContainer };
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