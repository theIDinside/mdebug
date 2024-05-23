#pragma once
#include <algorithm>
#include <numeric>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace utils {
constexpr std::vector<std::string_view>
split_string(std::string_view str, std::string_view delim) noexcept
{
  std::vector<std::string_view> result{};
  auto last = false;
  for (auto i = str.find(delim); i != std::string_view::npos || !last; i = str.find(delim)) {
    last = (i == std::string_view::npos);
    auto sub = str.substr(0, i);
    if (!sub.empty())
      result.push_back(sub);
    if (!last)
      str.remove_prefix(i + 1);
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
} // namespace utils