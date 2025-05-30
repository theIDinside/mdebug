/** LICENSE TEMPLATE */
#include "common.h"
#include <algorithm>
#include <optional>
#include <type_traits>

namespace mdb {
template <typename T>
concept Comparable = requires(const T &t) {
  { t == t } -> std::convertible_to<bool>;
};

template <typename Iterator> struct SpanResult
{
  using ref = decltype(*Iterator{});
  SpanResult(Iterator a, Iterator b) noexcept : found(true), begin(a), end(b) {}
  SpanResult() noexcept : found(false), begin(), end() {}

  std::pair<ref, ref>
  result() const noexcept
  {
    ASSERT(has_value(), "Result was not found!");
    return std::pair(*begin, *end);
  }

  constexpr bool
  has_value() const noexcept
  {
    return found;
  }

private:
  bool found;
  Iterator begin, end;
};

template <typename Container, typename ValueType, typename Fn>
constexpr auto
find_span(Container &c, const ValueType &v, Fn &&f)
{
  using It = typename Container::iterator;
  auto it = std::lower_bound(std::begin(c), std::end(c), v, f);
  if (it != std::end(c) && it != std::begin(c)) {
    auto s = it - 1;
    return SpanResult{s, it};
  } else {
    return SpanResult<It>{};
  }
}

template <typename Container, typename ValueType, typename Fn>
constexpr auto
lower_bound(Container &c, const ValueType &v, Fn &&f) noexcept -> std::optional<typename Container::iterator>
{
  if constexpr (std::is_const<Container>::value) {
    if (const auto it = std::lower_bound(c.cbegin(), c.cend(), v, f); it != std::end(c)) {
      return std::optional{it};
    } else {
      return std::nullopt;
    }
  } else {
    if (auto it = std::lower_bound(c.begin(), c.end(), v, f); it != std::end(c)) {
      return std::optional{it};
    } else {
      return std::nullopt;
    }
  }
}

template <typename Container, typename ValueType, typename Fn>
constexpr auto
upper_bound(Container &c, const ValueType &v, Fn &&f) noexcept
{
  if constexpr (std::is_const<Container>::value) {
    if (const auto it = std::upper_bound(c.cbegin(), c.cend(), v, f); it != std::end(c)) {
      return std::optional{it};
    } else {
      return std::nullopt;
    }
  } else {
    if (auto it = std::upper_bound(c.begin(), c.end(), v, f); it != std::end(c)) {
      return std::optional{it};
    } else {
      return std::nullopt;
    }
  }
}

template <typename Container, typename Fn>
constexpr auto
find_if(Container &c, Fn &&f) noexcept
{
  using ReturnType = decltype(std::optional{c.begin()});
  if constexpr (std::is_const<Container>::value) {
    if (const auto it = std::find_if(c.begin(), c.end(), f); it != std::end(c)) {
      return std::optional{it};
    } else {
      return ReturnType{};
    }
  } else {
    if (auto it = std::find_if(c.begin(), c.end(), f); it != std::end(c)) {
      return std::optional{it};
    } else {
      return ReturnType{};
    }
  }
}

template <typename Container, typename Fn>
constexpr auto
none_of(const Container &c, Fn &&fn) noexcept
{
  return std::none_of(c.begin(), c.end(), std::move(fn));
}

template <typename Container, Comparable T>
constexpr auto
any_of(const Container &c, const T &value) noexcept
{
  for (const auto &v : c) {
    if (v == value) {
      return true;
    }
  }

  return false;
}

template <typename Container, Comparable T>
constexpr auto
none_of(const Container &c, const T &value) noexcept
{
  return !any_of(c, value);
}

} // namespace mdb