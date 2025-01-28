/** LICENSE TEMPLATE */
#pragma once
#include <iterator>
#include <type_traits>
namespace mdb {
template <typename Container> class Skiperator
{
  Container &c;
  int skip;

  auto
  skip_it()
  {
    auto it = c.begin();
    const auto e = c.end();
    auto i = 0;
    while (it != e && i < skip) {
      ++it;
      ++i;
    }
    return it;
  }

  auto
  skip_it() const
  {
    auto it = c.cbegin();
    const auto e = c.cend();
    auto i = 0;
    while (it != e && i < skip) {
      ++it;
      ++i;
    }
    return it;
  }

public:
  template <typename It> struct Iterator
  {
    It iter;
    using IsConst = std::is_const<typename std::remove_reference<decltype(*iter)>::type>;
    using RefType =
      std::conditional_t<IsConst::value, typename Container::const_reference, typename Container::reference>;
    using PtrType =
      std::conditional_t<IsConst::value, typename Container::const_pointer, typename Container::pointer>;

    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = typename Container::value_type;
    using pointer = PtrType;
    using reference = RefType;
    using const_reference = typename Container::const_reference;

    auto
    operator*() noexcept -> std::conditional_t<IsConst::value, const_reference, reference>
    {
      return *iter;
    }

    reference
    operator*() const noexcept
    {
      return *iter;
    }

    auto
    operator->() noexcept -> PtrType
    {
      return iter.base();
    }

    Iterator &
    operator++() noexcept
    {
      ++iter;
      return *this;
    }

    Iterator
    operator++(int) noexcept
    {
      auto copy = Iterator{iter};
      ++(copy.iter);
      return copy;
    }

    friend bool
    operator==(const It &a, const It &b) noexcept
    {
      return a.it == b.it;
    }
  };

  explicit Skiperator(int skip, Container &c) noexcept : c(c), skip(skip) {}

  auto
  begin() noexcept
  {
    auto it = skip_it();
    return Iterator<decltype(c.begin())>{it};
  }

  auto
  end() noexcept
  {
    return Iterator<decltype(c.end())>{c.end()};
  }

  auto
  cbegin() const noexcept
  {
    const auto it = skip_it();
    return Iterator{it};
  }

  auto
  cend() const noexcept
  {
    return Iterator{c.cend()};
  }
};

} // namespace mdb