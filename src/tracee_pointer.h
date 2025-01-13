/** LICENSE TEMPLATE */
#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <functional>
#include <fmt/core.h>

template<typename T>
concept Integral = std::is_integral_v<T>;

template <typename T> class TraceePointer
{
public:
  using Type = typename std::remove_cv_t<T>;
  constexpr TraceePointer() noexcept : mRemoteAddress{0} {}
  constexpr TraceePointer(std::nullptr_t) noexcept : mRemoteAddress{0} {}
  constexpr TraceePointer &operator=(const TraceePointer &) = default;
  constexpr TraceePointer(const TraceePointer &) = default;
  constexpr TraceePointer(TraceePointer &&) = default;
  constexpr
  operator std::uintptr_t() const
  {
    return get();
  }
  constexpr TraceePointer(std::uintptr_t addr) noexcept : mRemoteAddress(addr) {}
  constexpr TraceePointer(T *t) noexcept : mRemoteAddress(reinterpret_cast<std::uintptr_t>(t)) {}
  constexpr ~TraceePointer() = default;

  // Utility function. When one needs to be sure we are offseting by *bytes* and not by sizeof(T) * n.
  friend TraceePointer<T> constexpr offset(TraceePointer<T> ptr, unsigned long long bytes) noexcept
  {
    return ptr.mRemoteAddress + bytes;
  }

  // `offset` is in N of T, not in bytes (unless T, of course, is a byte-like type)
  template <Integral OffsetT>
  constexpr TraceePointer
  operator+(OffsetT offset) const noexcept
  {
    const auto res = mRemoteAddress + (offset * type_size());
    return TraceePointer{res};
  }

  // `offset` is in N of T, not in bytes (unless T, of course, is a byte-like type)
  template <Integral OffsetT>
  constexpr TraceePointer
  operator-(OffsetT offset) const noexcept
  {
    const auto res = mRemoteAddress - (offset * type_size());
    return TraceePointer{res};
  }

  template <Integral OffsetT>
  constexpr TraceePointer &
  operator+=(OffsetT offset) noexcept
  {
    mRemoteAddress += (offset * type_size());
    return *this;
  }

  template <Integral OffsetT>
  constexpr TraceePointer &
  operator-=(OffsetT offset) noexcept
  {
    mRemoteAddress -= (offset * type_size());
    return *this;
  }

  constexpr TraceePointer &
  operator++() noexcept
  {
    mRemoteAddress += type_size();
    return *this;
  }

  constexpr TraceePointer
  operator++(int) noexcept
  {
    const auto current = mRemoteAddress;
    mRemoteAddress += type_size();
    return TraceePointer{current};
  }

  constexpr TraceePointer &
  operator--() noexcept
  {
    mRemoteAddress -= type_size();
    return *this;
  }

  constexpr TraceePointer
  operator--(int) noexcept
  {
    const auto current = mRemoteAddress;
    mRemoteAddress -= type_size();
    return TraceePointer{current};
  }

  uintptr_t
  get() const noexcept
  {
    return mRemoteAddress;
  }

  // Returns the size of the pointed-to type so we can do pointer arithmetics on it.
  // We handle the edge case of void pointers, by assuming an Architecture's "word size" (32-bit/64-bit)
  static constexpr unsigned long long
  type_size() noexcept
  {
    if constexpr (std::is_void_v<T>) {
      return 1;
    } else {
      return sizeof(T);
    }
  }

  /**
   * Cast this TraceePointer<T> to TraceePointer<U>. Most often used
   * for turning TraceePointer<void> into TraceePointer<U> where U is
   * some concrete type.
   */
  template <typename U>
  constexpr TraceePointer<U>
  as() const noexcept
  {
    return TraceePointer<U>{get()};
  }

  // Utility that could get called a lot when we want to do arbitrary
  // things with a TraceePointer<T> that doesn't involve the type T it's pointing to, like for instance comparing
  // if a ptr lands inside an address range. Use `as_void` for this (or the templated member function)
  constexpr TraceePointer<void>
  as_void() const noexcept
  {
    return as<void>();
  }

  template <typename U = T>
  constexpr friend bool
  operator<(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() < r.get();
  }

  template <typename U = T>
  constexpr friend bool
  operator<=(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() <= r.get();
  }

  template <typename U = T>
  constexpr friend bool
  operator>(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() > r.get();
  }

  template <typename U = T>
  constexpr friend bool
  operator>=(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() >= r.get();
  }

  template <typename U = T>
  constexpr friend bool
  operator==(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() == r.get();
  }

  template <typename U = T>
  constexpr friend bool
  operator!=(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() != r.get();
  }

  static constexpr auto
  Max() noexcept
  {
    return TraceePointer{UINTMAX_MAX};
  }

  static constexpr auto
  Min() noexcept
  {
    return TraceePointer{nullptr};
  }

private:
  std::uintptr_t mRemoteAddress;
};

template <typename T> struct std::hash<TraceePointer<T>>
{
  using argument_type = TraceePointer<T>;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return m.get();
  }
};

namespace fmt {
template <typename T> struct formatter<TraceePointer<T>>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(TraceePointer<T> const &tptr, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "0x{:x}", tptr.get());
  }
};

} // namespace fmt

using AddrPtr = TraceePointer<void>;
template <typename T> using TPtr = TraceePointer<T>;

template <typename T> using Option = std::optional<T>;

constexpr Option<AddrPtr>
to_addr(std::string_view s) noexcept
{
  if (s.starts_with("0x")) {
    s.remove_prefix(2);
  }

  uint64_t value;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value, 16);
  if (ec == std::errc() && ptr == s.data() + s.size()) {
    return AddrPtr{value};
  } else {
    return std::nullopt;
  }
}