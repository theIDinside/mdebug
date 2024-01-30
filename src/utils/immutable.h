#pragma once
#include "common.h"
#include <type_traits>
#include <utility>

template <typename T> class Immutable
{
  T data;

public:
  constexpr Immutable(T t) noexcept : data(t) {}
  constexpr Immutable(T &&t) noexcept : data(std::move(t)) {}
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
};

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

template <typename T> class NonNullPtr
{
  T *ptr;

public:
  explicit NonNullPtr(T *ptr __attribute__((nonnull))) noexcept : ptr(ptr)
  {
    if (ptr == nullptr) {
      PANIC("Explicit NonNullPtr was passed a nullptr, breaking the invariant.");
    }
  }

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

  [[gnu::returns_nonnull]]
  operator T *() noexcept
  {
    return ptr;
  }
};
