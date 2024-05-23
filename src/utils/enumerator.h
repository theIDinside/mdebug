#pragma once

#include "common.h"
#include <iterator>
#include <utils/indexing.h>
namespace utils {

template <typename C> concept HasReferenceAlias = requires(C c) { typename C::reference; };
template <typename C> concept HasIteratorAlias = requires(C c) { typename C::iterator; };
template <typename C> concept HasPointerAlias = requires(C c) { typename C::pointer; };
template <typename C> concept HasValueTypeAlias = requires(C c) { typename C::value_type; };

/** An enumerating view over `Container`. Only deals with immutable values (because, it is a view!)*/
template <typename Container> class EnumerateView
{
  Container &c;

public:
  template <typename IterValueType> struct Enumeration
  {
    Index index;
    IterValueType &T;
  };

  template <typename ContainerIterator = typename Container::iterator> class Enumerator
  {
    ContainerIterator iter;
    Index index;

  public:
    using IsConst = std::is_const<typename std::remove_reference<decltype(*iter)>::type>;
    static_assert(HasReferenceAlias<Container>,
                  "Your container type must provide a 'reference' type alias (using declaration or typedef)");
    static_assert(HasIteratorAlias<Container>,
                  "Your container type must provide a 'iterator' type alias (using declaration or typedef)");
    static_assert(HasPointerAlias<Container>,
                  "Your container type must provide a 'pointer' type alias (using declaration or typedef)");
    static_assert(HasValueTypeAlias<Container>,
                  "Your container type must provide a 'value_type' type alias (using declaration or typedef)");

    using RefType =
        std::conditional_t<IsConst::value, const typename Container::reference, typename Container::reference>;
    using PtrType =
        std::conditional_t<IsConst::value, const typename Container::pointer, typename Container::pointer>;

    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = Enumeration<typename Container::value_type>;
    using pointer = Enumeration<PtrType>;
    using reference = Enumeration<RefType>;

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

  EnumerateView(Container &c) noexcept : c(c) {}

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
};
} // namespace utils