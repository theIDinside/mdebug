/** LICENSE TEMPLATE */
#pragma once

namespace mdb {
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
} // namespace mdb

template <typename T> using Rev = mdb::Reversed<T>;