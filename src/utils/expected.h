#pragma once
#include "common.h"
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace utils {

template <typename T>
constexpr bool
trivial_destruct()
{
  if constexpr (std::is_array_v<T>) {
    return std::is_trivially_destructible_v<typename std::remove_reference<decltype(*T{})>>;
  } else {
    return std::is_trivially_destructible_v<T>;
  }
}

template <typename Err> struct Unexpected
{
  Err err;
};

template <typename Err>
auto
unexpected(const Err &err) noexcept
{
  return Unexpected<Err>{err};
}

template <typename Err>
auto
unexpected(Err &&err) noexcept
{
  return Unexpected<Err>{std::forward<Err>(err)};
}

// Base template for the variadic template
template <typename T, typename... Args> struct IsFirstTypeSame;

// Specialization to extract the first type and compare it with T
template <typename T, typename First, typename... Rest> struct IsFirstTypeSame<T, First, Rest...>
{
  static constexpr bool value = std::is_same<T, First>::value;
};

// Just a thin, stupid, inefficient wrapper around std::variant. It'll do for now.
template <typename T, typename Err> class Expected
{
  std::variant<T, Err> val_or_err;
  bool has_value;

public:
  template <typename... Args>
  Expected(Args &&...args) noexcept
    requires(!IsFirstTypeSame<Err, Args...>::value)
      : val_or_err(std::forward<Args>(args)...), has_value(true)
  {
    ASSERT(val_or_err.index() == 0, "You've broken the invariant");
  }

  Expected(Expected &&move) noexcept : val_or_err(std::move(move.val_or_err)), has_value(move.has_value) {}

  Expected(Err &&e) noexcept : val_or_err(std::move(e)), has_value(false) {}
  Expected(const Err &e) noexcept : val_or_err(e), has_value(false) {}

  Expected(const Unexpected<Err> &conv) : val_or_err(conv.err), has_value(false) {}
  Expected(Unexpected<Err> &&conv) : val_or_err(std::move(conv.err)), has_value(false) {}

  template <typename ConvertErr> Expected(Expected<T, ConvertErr> &&ExpectedWithValueRequiringConversion) noexcept
  {
    ASSERT(ExpectedWithValueRequiringConversion.is_expected(),
           "Conversion from expected that had a value, but was expected to be an error");
    val_or_err = std::move(ExpectedWithValueRequiringConversion.take_value());
    has_value = true;
  }

  ~Expected() noexcept = default;

  constexpr bool
  is_expected() const noexcept
  {
    return has_value;
  }

  constexpr bool
  is_error() const noexcept
  {
    return !is_expected();
  }

  T *
  operator->() noexcept
  {
    ASSERT(has_value, "Expected did not have a value");
    return std::get_if<T>(&val_or_err);
  }

  auto &
  operator*() & noexcept
  {
    ASSERT(has_value, "Expected did not have a value");
    return *std::get_if<T>(&val_or_err);
  }

  T&& expected(std::string_view errorMessage) && {
    if(is_error()) {
      PANIC(errorMessage);
    }
    return std::move(value());
  }

  T &
  value() & noexcept
  {
    ASSERT(has_value, "Expected did not have a value");
    return *std::get_if<T>(&val_or_err);
  }

  T &&
  value() && noexcept
  {
    ASSERT(has_value, "Expected did not have a value");
    return std::get<T>(std::move(val_or_err));
  }

  // Just make it explicit. Easier for everyone to know, we are *definitely* moving out of this value.
  T &&
  take_value() noexcept
  {
    ASSERT(has_value, "Expected did not have a value");
    auto &&moved = std::get<T>(std::move(val_or_err));
    has_value = false;
    return moved;
  }

  const T &
  value() const & noexcept
  {
    ASSERT(has_value, "Expected did not have a value");
    return std::get<T>(val_or_err);
  }

  Err &
  error() & noexcept
  {
    ASSERT(!has_value, "Expected have a value");
    return std::get<Err>(val_or_err);
  }

  Err &&
  take_error() noexcept
  {
    ASSERT(!has_value, "Expected have a value");
    return std::get<Err>(std::move(val_or_err));
  }

  Err &&
  error() && noexcept
  {
    ASSERT(!has_value, "Expected have a value");
    return std::get<Err>(std::move(val_or_err));
  }

  const Err &
  error() const & noexcept
  {
    ASSERT(!has_value, "Expected have a value");
    return std::get<Err>(val_or_err);
  }

  template <typename Transform>
  constexpr auto
  transform(Transform &&fn) && noexcept -> utils::Expected<FnResult<Transform, T>, Err>
  {
    using Return = FnResult<Transform, T>;
    if (has_value) {
      auto &&res = fn(take_value());
      return utils::Expected<Return, Err>{res};
    } else {
      return unexpected(take_error());
    }
  }

  template <typename NewErr, typename Transform>
  constexpr auto
  and_then(Transform &&fn) && noexcept -> FnResult<Transform, T>
  {
    if (has_value) {
      return fn(take_value());
    } else {
      return unexpected(NewErr{take_error()});
    }
  }
};

template <typename Pointee> struct is_smart_ptr : std::false_type
{
};
template <typename Pointee> struct is_smart_ptr<std::shared_ptr<Pointee>> : std::true_type
{
};
template <typename Pointee> struct is_smart_ptr<std::unique_ptr<Pointee>> : std::true_type
{
};

template <typename T> concept IsPointer = is_smart_ptr<T>::value || std::is_pointer_v<T>;

template <typename Fn>
auto
transform(const IsPointer auto &smart_ptr, Fn &&fn) noexcept -> std::optional<decltype(fn(*smart_ptr))>
{
  if (smart_ptr == nullptr) {
    return std::nullopt;
  }
  return std::make_optional(fn(*smart_ptr));
}

} // namespace utils