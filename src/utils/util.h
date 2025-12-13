/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include <algorithm>
#include <chrono>
#include <common/typedefs.h>
#include <numeric>
#include <optional>
#include <ranges>
#include <string_view>
#include <sys/user.h>
#include <type_traits>
#include <utility>
#include <vector>

namespace mdb {

template <typename T>
constexpr bool
WithinRange(T value, T startInclusive, T endInclusive) noexcept
  requires(std::is_trivially_copyable_v<T> && sizeof(T) < 8)
{
  return startInclusive <= value && endInclusive >= value;
}

template <typename T>
constexpr bool
WithinRange(const T &value, const T &startInclusive, const T &endInclusive) noexcept
  requires(!std::is_trivially_copyable_v<T> || sizeof(T) >= 8)
{
  return startInclusive <= value && endInclusive >= value;
}

template <typename T, auto Low, auto High>
constexpr bool
WithinRange(const T &value) noexcept
{
  static_assert(Low <= High, "You've passed an invalid range, low is larger than high");
  return WithinRange(value, Low, High);
}

template <typename ContainerType, typename ValueType>
constexpr bool
ContainsValue(const ContainerType &container, const ValueType &b) noexcept
{
  for (const auto &element : container) {
    if (element == b) {
      return true;
    }
  }
  return false;
}

template <typename... Args>
constexpr auto
FilterNullptr()
{
  return std::ranges::views::filter([](auto ptr) { return ptr != nullptr; });
}

constexpr std::optional<SessionId>
StrToPid(std::string_view str, bool hex) noexcept
{
  SessionId p;
  auto res = std::from_chars(str.begin(), str.end(), p, hex ? 16 : 10);
  if (res.ec == std::errc()) {
    return p;
  }
  return {};
}

// Just a type that signals that who ever holds this one, should call `delete` on t
template <typename T> struct OwningPointer
{
  T *t;

  constexpr T *
  operator->() noexcept
  {
    return t;
  }

  constexpr const T *
  operator->() const noexcept
  {
    return t;
  }

  constexpr
  operator T *() noexcept
  {
    return t;
  }
  constexpr
  operator T *() const noexcept
  {
    return t;
  }

  constexpr
  operator const T *() noexcept
  {
    return t;
  }
  constexpr
  operator const T *() const noexcept
  {
    return t;
  }
};

template <typename Delimiter = std::string_view>
constexpr std::vector<std::string_view>
SplitString(std::string_view str, Delimiter delim) noexcept
{
  std::vector<std::string_view> result{};
  auto last = false;
  for (auto i = str.find(delim); i != std::string_view::npos || !last; i = str.find(delim)) {
    last = (i == std::string_view::npos);
    auto sub = str.substr(0, i);
    if (!sub.empty()) {
      result.push_back(sub);
    }
    if (!last) {
      str.remove_prefix(i + 1);
    }
  }
  return result;
}

template <typename Fn, typename Range>
auto
position(const Range &rng, Fn &&fn) noexcept -> std::optional<size_t>
{
  const auto it = std::ranges::find_if(rng, std::move(fn));
  if (it == std::end(rng)) {
    return {};
  } else {
    return std::distance(rng.begin(), it);
  }
}

template <typename Fn, typename Range>
auto
sort(Range &r, Fn &&fn) noexcept
{
  std::sort(std::begin(r), std::end(r), std::forward<Fn>(fn));
}

template <typename Range, typename Fn>
auto
accumulate(Range &r, Fn &&fn) noexcept -> decltype(fn({}, decltype(*std::begin(r)){}))
{
  using T = decltype(fn({}, decltype(*std::begin(r)){}));
  // using T = std::invoke_result_t<Fn, AccT, decltype(*std::begin(r))>;
  return std::accumulate(std::begin(r), std::end(r), T{ 0 }, std::forward<Fn>(fn));
}
template <typename T>
constexpr auto
castenum(T &&t) -> decltype(std::to_underlying(t))
{
  return std::to_underlying(t);
}

constexpr auto
SystemPagesInBytes(int pageCount) noexcept -> size_t
{
  return pageCount * PAGE_SIZE;
}

template <typename T, typename U>
constexpr bool
IsSame()
{
  if constexpr (std::is_same_v<std::remove_cvref_t<T>, std::remove_cvref_t<U>>) {
    return true;
  }
  return false;
}

template <typename CA, typename CB = CA>
constexpr auto
CopyTo(const CA &c, CB &out)
{
  if constexpr (requires(CA i, CB o) {
                  i.size();
                  o.reserve(1024);
                  out.size();
                }) {
    out.reserve(c.size() + out.size());
    std::copy(c.begin(), c.end(), std::back_inserter(out));
  } else {
    auto index = 0;
    while (index < out.size() && index < c.size()) {
      out[index] = c[index];
      ++index;
    }
  }
}

template <typename CA, typename CB = CA>
constexpr auto
CopyNTo(const CA &c, CB &out, size_t n)
{
  if constexpr (requires(CA i, CB o) {
                  i.size();
                  o.reserve(1024);
                  out.size();
                }) {
    const auto total = std::min(std::size(c), n);
    out.reserve(std::size(c) + total);
    std::copy(c.begin(), c.begin() + total, std::back_inserter(out));
  } else {
    auto index = 0;
    const auto max = std::min(std::min(out.size(), c.size()), n);
    while (index < max) {
      out[index] = c[index];
      ++index;
    }
  }
}

template <typename C1, typename C2, typename Fn>
constexpr auto
TransformCopyTo(C1 &c, C2 &out, Fn transform)
{
  std::transform(c.begin(), c.end(), std::back_inserter(out), transform);
}

} // namespace mdb

template <typename T> struct Default
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &context)
  {
    return context.begin();
  }
};

// Debug adapter protocol messages are json, and as such may need escaping (in the cases where we can't control the
// format up front.)
struct DebugAdapterProtocolString
{
  std::string_view mStringView;
  static constexpr auto mQuoteChar = '"';
  static constexpr auto mEscapeChar = '\\';

  template <typename OutputIterator>
  constexpr OutputIterator
  copy(OutputIterator out) const
  {
    for (const auto &c : mStringView) {
      switch (c) {
      case '\0':
        *out++ = mEscapeChar;
        *out++ = '0';
        break;
      case '\a':
        *out++ = mEscapeChar;
        *out++ = 'a';
        break;
      case '\b':
        *out++ = mEscapeChar;
        *out++ = 'b';
        break;
      case '\t':
        *out++ = mEscapeChar;
        *out++ = 't';
        break;
      case '\n':
        *out++ = mEscapeChar;
        *out++ = 'n';
        break;
      case '\v':
        *out++ = mEscapeChar;
        *out++ = 'v';
        break;
      case '\f':
        *out++ = mEscapeChar;
        *out++ = 'f';
        break;
      case '\r':
        *out++ = mEscapeChar;
        *out++ = 'r';
        break;
      case '\\':
        *out++ = mEscapeChar;
        *out++ = mEscapeChar;
        break;
      case '"':
        *out++ = mEscapeChar;
        *out++ = mQuoteChar;
        break;
      default:
        *out++ = c;
      }
    }
    return out;
  }
};

template <> struct std::formatter<DebugAdapterProtocolString>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  constexpr auto
  format(const DebugAdapterProtocolString &escapeView, FormatContext &ctx) const
  {
    return escapeView.copy(ctx.out());
  }
};

constexpr auto
MicroSecondsSince(auto start) noexcept
{
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
    .count();
}

constexpr auto
MilliSecondsSince(auto start) noexcept
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start)
    .count();
}

template <class T, class F>
T
ValueOrElse(std::optional<T> &&opt, F &&f)
{
  if (opt) {
    return *opt;
  }
  return std::invoke(std::forward<F>(f));
}

using DAPStringView = DebugAdapterProtocolString;