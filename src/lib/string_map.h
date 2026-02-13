#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace mdb {

// Transparent hash functor for string types
struct StringHash
{
  using is_transparent = void;

  [[nodiscard]] constexpr size_t
  operator()(const char *str) const noexcept
  {
    return std::hash<std::string_view>{}(str);
  }

  [[nodiscard]] constexpr size_t
  operator()(std::string_view str) const noexcept
  {
    return std::hash<std::string_view>{}(str);
  }

  [[nodiscard]] constexpr size_t
  operator()(const std::string &str) const noexcept
  {
    return std::hash<std::string_view>{}(str);
  }
};

// Transparent equality comparator for string types
struct StringEqual
{
  using is_transparent = void;

  [[nodiscard]] constexpr bool
  operator()(std::string_view lhs, std::string_view rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(std::string_view lhs, const std::string &rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(std::string_view lhs, const char *rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(const std::string &lhs, std::string_view rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(const std::string &lhs, const std::string &rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(const std::string &lhs, const char *rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(const char *lhs, std::string_view rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(const char *lhs, const std::string &rhs) const noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] constexpr bool
  operator()(const char *lhs, const char *rhs) const noexcept
  {
    return std::string_view(lhs) == std::string_view(rhs);
  }
};

template <typename ValueType>
using StringViewMap = std::unordered_map<std::string_view, ValueType, StringHash, StringEqual>;

template <typename ValueType>
using StringMap = std::unordered_map<std::string, ValueType, StringHash, StringEqual>;

} // namespace mdb
