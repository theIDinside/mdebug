#pragma once

#include <iterator>
#include <type_traits>

namespace sym::dw {
struct DieMetaData;
}

namespace utils {

template <typename Container, typename Fn> class FilterView
{
  using non_const_value_type = std::remove_const_t<Container>;
  using const_value_type = std::add_const_t<non_const_value_type>;
  Container &c;

  // Container &c;
  Fn f;

public:
  template <typename UnderlyingIter> struct Iterator
  {
  private:
    UnderlyingIter iter;
    UnderlyingIter end;
    Fn f;
    using IsConst = std::is_const<typename std::remove_reference<decltype(*iter)>::type>;

    void
    iterate_until_predicate_passes() noexcept
    {
      while (keep_going()) {
        ++iter;
      }
    }

    bool
    keep_going() noexcept
    {
      return iter != end && !f(*iter);
    }

  public:
    // using FnPtr = bool (*)(typename Container::reference);
    using non_const_value_type_it = std::remove_const_t<UnderlyingIter>;
    using const_value_type_it = std::add_const_t<non_const_value_type_it>;
    friend std::conditional_t<std::is_same<UnderlyingIter, non_const_value_type_it>::value,
                              Iterator<const_value_type_it>, void>;

    Iterator(UnderlyingIter it, UnderlyingIter end, Fn f) noexcept : iter(it), end(end), f(f)
    {
      iterate_until_predicate_passes();
    }

    template <class U = UnderlyingIter>
    Iterator(
        std::enable_if_t<std::is_same<U, const_value_type_it>::value, Iterator<non_const_value_type_it> const &>
            other)
        : iter(other.iter), end(other.end), f(other.f)
    {
      iterate_until_predicate_passes();
    }

    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = typename Container::value_type;
    using pointer = typename Container::pointer;
    using reference = typename Container::reference;
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

    pointer
    operator->() noexcept
    {
      return iter.base();
    }

    Iterator &
    operator++() noexcept
    {
      do {
        ++iter;
      } while (keep_going());
      return *this;
    }

    Iterator
    operator++(int) noexcept
    {
      Iterator copy{iter, end, f};
      do {
        ++copy.iter;
      } while (copy.keep_going());
      return copy;
    }

    friend bool
    operator==(const Iterator &a, const Iterator &b) noexcept
    {
      return a.iter == b.iter;
    }
  };

  friend std::conditional_t<std::is_same<Container, non_const_value_type>::value, FilterView<const_value_type, Fn>,
                            void>;

  template <class U = Container>
  FilterView(
      std::enable_if_t<std::is_same<U, const_value_type>::value, FilterView<non_const_value_type, Fn> const &>
          other)
      : c(other.c), f(other.f)
  {
  }

  FilterView(Container &c, Fn f) noexcept : c(c), f(f) {}

  auto
  begin() noexcept
  {
    return Iterator<decltype(c.begin())>{c.begin(), c.end(), f};
  }

  auto
  end() noexcept
  {
    return Iterator<decltype(c.end())>{c.end(), c.end(), f};
  }

  auto
  cbegin() const noexcept
  {
    return Iterator{c.cbegin(), c.cend(), f};
  }

  auto
  cend() const noexcept
  {
    return Iterator{c.cend(), c.cend(), f};
  }
};
} // namespace utils