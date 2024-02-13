#pragma once
#include "common.h"
#include <type_traits>
#include <utility>

template <typename T> class Immutable
{
  T data;

public:
  constexpr Immutable(const T &t) noexcept : data(t) {}

  constexpr Immutable(T &&t) noexcept
    requires(!std::is_trivial_v<T> && !std::is_trivially_copyable_v<T>)
      : data(std::move(t))
  {
  }
  constexpr Immutable(const Immutable &) noexcept = default;
  constexpr Immutable(Immutable &&other) noexcept = default;
  constexpr Immutable &operator=(const Immutable &) noexcept = default;
  constexpr Immutable &operator=(Immutable &&other) noexcept = default;

  template <typename... Args> Immutable(Args... args) noexcept : data(std::forward<Args>(args)...) {}

  constexpr operator const T &() const & { return data; }

  constexpr const T &
  operator*() const & noexcept
  {
    return data;
  }

  constexpr const T *
  operator->() const noexcept
  {
    return std::addressof(data);
  }

  constexpr
  operator T &&() &&
  {
    return std::move(data);
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs.data <=> rhs.data;
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const T &rhs) noexcept
  {
    return lhs.data <=> rhs;
  }

  constexpr friend auto
  operator<=>(const T &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs <=> rhs.data;
  }

  // An Immutable<T> member variable, might want to hand out a mutable reference to a sub object. This is
  // absolutely fine.
  constexpr T &
  mut() noexcept
  {
    return data;
  }
};

template <typename T, typename U>
constexpr auto
operator+(const Immutable<T> &l, const Immutable<U> &r)
{
  // explicit coercion.
  return (*l) + (*r);
}

namespace fmt {

template <typename T> struct formatter<Immutable<T>>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const Immutable<T> &var, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "{}", *var);
  }
};
} // namespace fmt

template <typename T> struct NonNullPtr
{
  T *ptr;

  T &
  operator*() noexcept
  {
    return *ptr;
  }

  [[gnu::returns_nonnull]] T *
  operator->() noexcept
  {
    return ptr;
  }

  [[gnu::returns_nonnull]] const T *
  operator->() const noexcept
  {
    return ptr;
  }

  constexpr
  operator T &() noexcept
  {
    return *ptr;
  }

  [[gnu::returns_nonnull]]
  operator T *() noexcept
  {
    return ptr;
  }

  [[gnu::returns_nonnull]] operator const T *() const noexcept { return ptr; }
};

template <typename U>
static constexpr auto
NonNull(U &ref) noexcept
{
  return NonNullPtr<U>{.ptr = &ref};
}