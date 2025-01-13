/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include <type_traits>
#include <utility>

template <typename T> class Immutable
{
  T data;
  using SelfT = Immutable<T>;

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

  constexpr
  operator const T &() const &
  {
    return data;
  }

  constexpr T
  clone() const noexcept
  {
    return data;
  }

  constexpr const T &
  operator*() const & noexcept
  {
    return data;
  }

  constexpr
  operator std::optional<T>() const
  {
    return std::optional<T>{data};
  }

  constexpr const T *
  operator->() const noexcept
    requires(!IsSmartPointer<T>)
  {
    return std::addressof(data);
  }

  constexpr const auto *
  operator->() const noexcept
    requires(IsSmartPointer<T>)
  {
    return data.get();
  }

  constexpr
  operator T &&() &&
  {
    return std::move(data);
  }

  constexpr operator const T&() & {
    return data;
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

  constexpr auto
  begin() const noexcept
    requires(IsRange<T>)
  {
    return data.cbegin();
  }

  constexpr auto
  end() const noexcept
    requires(IsRange<T>)
  {
    return data.cend();
  }

  friend constexpr auto
  operator-(const Immutable &l, const T &r)
  {
    // explicit coercion.
    return (*l) - r;
  }

  friend constexpr auto
  operator-(const T &l, const Immutable<T> &r)
  {
    // explicit coercion.
    return l - (*r);
  }

  friend constexpr auto
  operator+(const Immutable<T> &l, const T &r)
  {
    // explicit coercion.
    return (*l) + r;
  }

  friend constexpr auto
  operator+(const T &l, const Immutable<T> &r)
  {
    // explicit coercion.
    return l + (*r);
  }

  // friend constexpr auto
  // operator==(const SelfT &l, std::nullptr_t) noexcept
  //   requires(IsSmartPointer<T>)
  // {
  //   return l.data.get() == nullptr;
  // }

  // friend constexpr auto
  // operator!=(const SelfT &l, std::nullptr_t) noexcept
  //   requires(IsSmartPointer<T>)
  // {
  //   return l.data.get() != nullptr;
  // }

  friend constexpr auto
  operator==(const SelfT &l, const SelfT &r) noexcept
  {
    return l.data == r.data;
  }

  friend constexpr auto
  operator==(const SelfT &l, const auto &r) noexcept
  {
    return l.data == r;
  }

  friend constexpr bool
  operator==(const T &r, const SelfT &l) noexcept
  {
    return l.data == r;
  }

  friend constexpr bool
  operator!=(const SelfT &l, const SelfT &r) noexcept
  {
    return !(l.data == r.data);
  }

  friend constexpr auto
  operator!=(const SelfT &l, const auto &r) noexcept
  {
    return !(l.data == r);
  }

  friend constexpr bool
  operator!=(const T &l, const SelfT &r) noexcept
  {
    return !(r.data == l);
  }

  constexpr const T &
  as_t() const noexcept
  {
    return data;
  }
};

template <> class Immutable<std::string>
{
  using T = std::string;
  T data;

public:
  constexpr Immutable(const T &t) noexcept : data(t) {}
  constexpr Immutable(T &&t) noexcept : data(std::move(t)) {}

  constexpr Immutable(const Immutable &) noexcept = default;
  constexpr Immutable(Immutable &&other) noexcept = default;
  constexpr Immutable &operator=(const Immutable &) noexcept = default;
  constexpr Immutable &operator=(Immutable &&other) noexcept = default;

  template <typename... Args> Immutable(Args... args) noexcept : data(std::forward<Args>(args)...) {}

  constexpr
  operator const std::string_view() const &
  {
    return data;
  }
  constexpr
  operator const std::optional<std::string_view>() const &
  {
    return data;
  }

  constexpr std::string_view
  string_view() const noexcept
  {
    return data;
  }

  constexpr const std::string_view
  operator*() const & noexcept
  {
    return std::string_view{data};
  }

  constexpr operator const T&() & {
    return data;
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

template <typename T> class Immutable<std::unique_ptr<T>>
{
  std::unique_ptr<T> data;

public:
  // Unique ptrs never copy
  constexpr Immutable(const Immutable &) noexcept = delete;
  constexpr Immutable &operator=(const Immutable &) noexcept = delete;

  constexpr Immutable(std::unique_ptr<T> &&t) noexcept : data(std::move(t)) {}
  constexpr Immutable(Immutable &&other) noexcept = default;
  constexpr Immutable &operator=(Immutable &&other) noexcept = default;

  template <typename... Args>
  Immutable(Args... args) noexcept : data(std::make_unique<T>(std::forward<Args>(args)...))
  {
  }

  constexpr
  operator const T &() const &
  {
    return *data;
  }

  constexpr const T &
  operator*() const & noexcept
  {
    return *data;
  }

  constexpr const T *
  operator->() const noexcept
  {
    return data.get();
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
    return *(lhs.data) <=> rhs;
  }

  constexpr friend auto
  operator<=>(const T &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs <=> *(rhs.data);
  }

  // An Immutable<T> member variable, might want to hand out a mutable reference to a sub object. This is
  // absolutely fine.
  constexpr T &
  mut() noexcept
  {
    return *data;
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

  constexpr
  operator T &() const noexcept
  {
    return *ptr;
  }

  [[gnu::returns_nonnull]] operator T *() noexcept { return ptr; }

  [[gnu::returns_nonnull]] operator const T *() const noexcept { return ptr; }
};

template <typename U>
static constexpr auto
NonNull(U &ref) noexcept
{
  return NonNullPtr<U>{.ptr = &ref};
}

template <typename T>
using ImmutablePtr = Immutable<NonNullPtr<T>>;