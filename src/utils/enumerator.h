#pragma once

#include <iterator>
namespace utils {
/** An enumerating view over `Container`. Only deals with immutable values (because, it is a view!)*/
template <typename Container> class EnumerateView
{
  const Container &c;

public:
  template <typename IterValueType> struct Enumeration
  {
    int index;
    IterValueType T;
  };

  template <typename ContainerIterator = typename Container::iterator> class Enumerator
  {
    ContainerIterator iter;
    int index;

  public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = Enumeration<typename Container::value_type>;
    using pointer = Enumeration<typename Container::pointer>;
    using reference = Enumeration<typename Container::reference>;

    Enumerator(ContainerIterator iter, int index) noexcept : iter(iter), index(index) {}
    ~Enumerator() noexcept = default;

    auto
    operator++(int)
    {
      iter++;
      index++;
      return Enumerator{iter, index};
    }

    auto &
    operator++()
    {
      ++iter;
      ++index;
      return *this;
    }

    auto
    operator->() const noexcept
    {
      return Enumeration<decltype(*iter)>{index, *iter};
    }

    auto
    operator*() const noexcept
    {
      return Enumeration<decltype(*iter)>{index, *iter};
    }

    auto
    operator==(const Enumerator &other) noexcept
    {
      return iter == other.iter;
    }

    auto
    operator!=(const Enumerator &o) noexcept
    {
      return !(*this == o);
    }
  };

  EnumerateView(const Container &c) noexcept : c(c) {}

  Enumerator<decltype(c.begin())>
  begin() noexcept
  {
    return Enumerator<decltype(c.begin())>{c.begin(), 0};
  }

  Enumerator<decltype(c.end())>
  end() noexcept
  {
    return Enumerator<decltype(c.end())>{c.end(), 0};
  }

  Enumerator<decltype(c.cbegin())>
  cbegin() const noexcept
  {
    return Enumerator<decltype(c.cbegin())>{c.cbegin(), 0};
  }

  Enumerator<decltype(c.cend())>
  cend() const noexcept
  {
    return Enumerator<decltype(c.cend())>{c.cend(), 0};
  }

  Enumerator<decltype(c.cbegin())>
  begin() const noexcept
  {
    return Enumerator<decltype(c.cbegin())>{c.cbegin(), 0};
  }

  Enumerator<decltype(c.cend())>
  end() const noexcept
  {
    return Enumerator<decltype(c.cend())>{c.cend(), 0};
  }
};
} // namespace utils