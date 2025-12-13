/** LICENSE TEMPLATE */
#pragma once

#include "common.h"
#include <concepts>
#include <iterator>
#include <utils/indexing.h>
namespace mdb {
template <typename C> concept HasReferenceAlias = requires(C c) { typename C::reference; };
template <typename C> concept HasIteratorAlias = requires(C c) { typename C::iterator; };
template <typename C> concept HasPointerAlias = requires(C c) { typename C::pointer; };
template <typename C> concept HasValueTypeAlias = requires(C c) { typename C::value_type; };

template <std::integral IndexType = size_t, std::ranges::range R>
auto
Enumerate(const R &r)
{
  struct Iterator
  {
    using BaseIt = std::ranges::iterator_t<const R>; // use iterator_t<const R> directly
    BaseIt it;
    IndexType index;

    constexpr auto
    operator*() const
    {
      return std::pair{ index, *it };
    }

    constexpr Iterator &
    operator++()
    {
      ++it;
      ++index;
      return *this;
    }

    constexpr bool
    operator!=(const Iterator &other) const
    {
      return it != other.it;
    }
  };

  struct WrappedRange
  {
    const R &r;

    constexpr auto
    begin()
    {
      return Iterator{ std::ranges::begin(r), 0 };
    }
    constexpr auto
    end()
    {
      return Iterator{ std::ranges::end(r), 0 };
    }
  };

  return WrappedRange{ r };
}

} // namespace mdb