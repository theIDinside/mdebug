/** LICENSE TEMPLATE */
#pragma once

namespace utils {

template <typename C> class Reversed
{
  const C &container;

public:
  explicit Reversed(const C &c) noexcept : container(c) {}

  auto
  begin() noexcept
  {
    return container.rbegin();
  }

  auto
  end() noexcept
  {
    return container.rend();
  }
};
} // namespace utils

template <typename T> using Rev = utils::Reversed<T>;