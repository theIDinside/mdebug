#pragma once
#include <string_view>
#include <vector>

namespace utils {
constexpr std::vector<std::string_view>
split_string(std::string_view str, std::string_view delim) noexcept
{
  std::vector<std::string_view> result{};
  auto last = false;
  for (auto i = str.find(delim); i != std::string_view::npos || !last; i = str.find(",")) {
    last = (i == std::string_view::npos);
    auto sub = str.substr(0, i);
    if (!sub.empty())
      result.push_back(sub);
    if (!last)
      str.remove_prefix(i + 1);
  }
  return result;
}
} // namespace utils