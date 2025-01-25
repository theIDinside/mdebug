/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include <algorithm>
#include <numeric>
#include <optional>
#include <ranges>
#include <string_view>
#include <type_traits>
#include <typedefs.h>
#include <utility>
#include <vector>

namespace utils {

template <typename... Args>
constexpr auto
FilterNullptr()
{
  return std::ranges::views::filter([](auto ptr) { return ptr != nullptr; });
}

constexpr std::optional<Pid>
StrToPid(std::string_view str, bool hex) noexcept
{
  Pid p;
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

constexpr std::vector<std::string_view>
split_string(std::string_view str, std::string_view delim) noexcept
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
  return std::accumulate(std::begin(r), std::end(r), T{0}, std::forward<Fn>(fn));
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
  if constexpr (requires(CB o) { o.reserve(1024); }) {
    out.reserve(c.size());
    std::copy(c.begin(), c.end(), std::back_inserter(out));
  } else {
    auto index = 0;
    while (index < out.size() && index < c.size()) {
      out[index] = c[index];
      ++index;
    }
  }
}

template <typename C, typename Fn>
constexpr auto
TransformCopyTo(C &c, C &out, Fn transform)
{
  std::transform(c.begin(), c.end(), std::back_inserter(out), transform);
}

} // namespace utils

template <typename T> struct Default
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &context)
  {
    return context.begin();
  }
};