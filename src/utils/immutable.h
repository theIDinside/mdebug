/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include <type_traits>
#include <utility>

namespace mdb {
template <typename T> class Immutable
{
  T mData;
  using SelfT = Immutable<T>;

public:
  constexpr Immutable(const T &t) noexcept : mData(t) {}

  constexpr Immutable(T &&t) noexcept
    requires(!std::is_trivial_v<T> && !std::is_trivially_copyable_v<T>)
      : mData(std::move(t))
  {
  }
  constexpr Immutable(const Immutable &) noexcept = default;
  constexpr Immutable(Immutable &&other) noexcept = default;
  constexpr Immutable &operator=(const Immutable &) noexcept = default;
  constexpr Immutable &operator=(Immutable &&other) noexcept = default;

  template <typename... Args> Immutable(Args... args) noexcept : mData(std::forward<Args>(args)...) {}

  constexpr
  operator const T &() const &
  {
    return mData;
  }

  constexpr T
  Clone() const noexcept
  {
    return mData;
  }

  constexpr const T &
  operator*() const & noexcept
  {
    return mData;
  }

  constexpr
  operator std::optional<T>() const
  {
    return std::optional<T>{mData};
  }

  constexpr const T *
  operator->() const noexcept
    requires(!mdb::IsSmartPointer<T>)
  {
    return std::addressof(mData);
  }

  constexpr const auto *
  operator->() const noexcept
    requires(mdb::IsSmartPointer<T>)
  {
    return mData.get();
  }

  constexpr
  operator T &&() &&
  {
    return std::move(mData);
  }

  constexpr
  operator const T &() &
  {
    return mData;
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs.mData <=> rhs.mData;
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const T &rhs) noexcept
  {
    return lhs.mData <=> rhs;
  }

  constexpr friend auto
  operator<=>(const T &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs <=> rhs.mData;
  }

  // Escape hatch for when we want to cache something perhaps. Will possibly change. Don't rely on this method.
  constexpr T &
  mut() noexcept
  {
    return mData;
  }

  constexpr auto
  begin() const noexcept
    requires(mdb::IsRange<T>)
  {
    return mData.cbegin();
  }

  constexpr auto
  end() const noexcept
    requires(mdb::IsRange<T>)
  {
    return mData.cend();
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

  friend constexpr auto
  operator==(const SelfT &l, const SelfT &r) noexcept
  {
    return l.mData == r.mData;
  }

  friend constexpr auto
  operator==(const SelfT &l, const auto &r) noexcept
  {
    return l.mData == r;
  }

  friend constexpr bool
  operator==(const T &r, const SelfT &l) noexcept
  {
    return l.mData == r;
  }

  friend constexpr bool
  operator!=(const SelfT &l, const SelfT &r) noexcept
  {
    return !(l.mData == r.mData);
  }

  friend constexpr auto
  operator!=(const SelfT &l, const auto &r) noexcept
  {
    return !(l.mData == r);
  }

  friend constexpr bool
  operator!=(const T &l, const SelfT &r) noexcept
  {
    return !(r.mData == l);
  }

  constexpr const T &
  Cast() const noexcept
  {
    return mData;
  }
};

template <> class Immutable<std::string>
{
  using T = std::string;
  T mData;

public:
  constexpr Immutable(const T &t) noexcept : mData(t) {}
  constexpr Immutable(T &&t) noexcept : mData(std::move(t)) {}

  constexpr Immutable(const Immutable &) noexcept = default;
  constexpr Immutable(Immutable &&other) noexcept = default;
  constexpr Immutable &operator=(const Immutable &) noexcept = default;
  constexpr Immutable &operator=(Immutable &&other) noexcept = default;

  template <typename... Args> Immutable(Args... args) noexcept : mData(std::forward<Args>(args)...) {}

  constexpr
  operator const std::string_view() const &
  {
    return mData;
  }
  constexpr
  operator const std::optional<std::string_view>() const &
  {
    return mData;
  }

  constexpr std::string_view
  StringView() const noexcept
  {
    return mData;
  }

  constexpr const std::string_view
  operator*() const & noexcept
  {
    return std::string_view{mData};
  }

  constexpr
  operator const T &() &
  {
    return mData;
  }

  constexpr
  operator T &&() &&
  {
    return std::move(mData);
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs.mData <=> rhs.mData;
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const T &rhs) noexcept
  {
    return lhs.mData <=> rhs;
  }

  constexpr friend auto
  operator<=>(const T &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs <=> rhs.mData;
  }

  // If this string represents a file path, and contains a /, return the last component
  // If no '/' is found, return the entire string.
  constexpr std::string_view
  FileName() const noexcept
  {
    auto index = mData.find_last_of('/');
    if (index == std::string::npos) {
      return StringView();
    }

    return std::string_view{mData}.substr(index + 1);
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
    return lhs.mData <=> rhs.mData;
  }

  constexpr friend auto
  operator<=>(const Immutable<T> &lhs, const T &rhs) noexcept
  {
    return *(lhs.mData) <=> rhs;
  }

  constexpr friend auto
  operator<=>(const T &lhs, const Immutable<T> &rhs) noexcept
  {
    return lhs <=> *(rhs.mData);
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
} // namespace mdb

namespace fmt {
template <typename T> using Immutable = mdb::Immutable<T>;
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
namespace mdb {
template <typename T> struct NonNullPtr
{
  T *ptr;

  constexpr T &
  operator*() noexcept
  {
    return *ptr;
  }

  [[gnu::returns_nonnull]] constexpr T *
  operator->() noexcept
  {
    return ptr;
  }

  [[gnu::returns_nonnull]] constexpr const T *
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

  [[gnu::returns_nonnull]] constexpr
  operator T *() noexcept
  {
    return ptr;
  }

  [[gnu::returns_nonnull]] constexpr
  operator const T *() const noexcept
  {
    return ptr;
  }
};

template <typename U>
static constexpr auto
NonNull(U &ref) noexcept
{
  return NonNullPtr<U>{.ptr = &ref};
}

template <typename T> using ImmutablePtr = Immutable<NonNullPtr<T>>;
} // namespace mdb