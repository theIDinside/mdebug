/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace mdb {
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

template <typename ExpValue> struct ExpectedValue
{
  ExpValue mValue;
};

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

template <typename T>
constexpr auto
expected(T &&value) noexcept
{
  return ExpectedValue<T>{std::move(value)};
}

template <typename T>
constexpr auto
expected(const T &value) noexcept
{
  return ExpectedValue<T>{value};
}

// Base template for the variadic template
template <typename T, typename... Args> struct IsFirstTypeSame;

// Specialization to extract the first type and compare it with T
template <typename T, typename First, typename... Rest> struct IsFirstTypeSame<T, First, Rest...>
{
  static constexpr bool value = std::is_same<T, First>::value;
};

// Just a thin, stupid, inefficient wrapper around std::variant. It'll do for now.
template <typename ActualT, typename Err> class Expected
{
  static_assert(!std::is_same_v<Err, void>,
                "Expected types where err is void is not supported. Why use expected at all, at that point?");

  using T = std::conditional_t<std::is_same_v<ActualT, void>, bool, ActualT>;

  std::variant<T, Err> val_or_err;
  bool mHasExpectedValue;

public:
  template <typename... Args>
  constexpr Expected(Args &&...args) noexcept
    requires(!IsFirstTypeSame<Err, Args...>::value)
      : val_or_err(args...), mHasExpectedValue(true)
  {
    ASSERT(val_or_err.index() == 0, "You've broken the invariant");
  }

  constexpr Expected(T &&value) noexcept
      : val_or_err(std::in_place_type<T>, std::forward<T>(value)), mHasExpectedValue(true)
  {
  }

  constexpr Expected(Err &&error) noexcept
      : val_or_err(std::in_place_type<Err>, std::forward<Err>(error)), mHasExpectedValue(false)
  {
  }

  constexpr Expected() noexcept
    requires(std::is_same_v<ActualT, void>)
      : val_or_err(true), mHasExpectedValue(true)
  {
  }

  constexpr Expected(Expected &&move) noexcept
      : val_or_err(std::move(move.val_or_err)), mHasExpectedValue(move.mHasExpectedValue)
  {
  }

  constexpr Expected(const Err &e) noexcept : val_or_err(e), mHasExpectedValue(false) {}

  constexpr Expected(ExpectedValue<T> &&value) noexcept
      : val_or_err(std::in_place_type<T>, std::move(value.mValue)), mHasExpectedValue(true)
  {
  }
  constexpr Expected(const ExpectedValue<T> &value) noexcept
      : val_or_err(std::in_place_type<T>, value.mValue), mHasExpectedValue(true)
  {
  }

  constexpr Expected(const Unexpected<Err> &conv) : val_or_err(conv.err), mHasExpectedValue(false) {}
  constexpr Expected(Unexpected<Err> &&conv) : val_or_err(std::move(conv.err)), mHasExpectedValue(false) {}

  template <typename ConvertErr> Expected(Expected<T, ConvertErr> &&ExpectedWithValueRequiringConversion) noexcept
  {
    ASSERT(ExpectedWithValueRequiringConversion.is_expected(),
           "Conversion from expected that had a value, but was expected to be an error");
    val_or_err = std::move(ExpectedWithValueRequiringConversion.take_value());
    mHasExpectedValue = true;
  }

  ~Expected() noexcept = default;

  constexpr bool
  is_expected() const noexcept
  {
    return mHasExpectedValue;
  }

  constexpr bool
  is_error() const noexcept
  {
    return !is_expected();
  }

  T *
  operator->() noexcept
  {
    ASSERT(mHasExpectedValue, "Expected did not have a value");
    return std::get_if<T>(&val_or_err);
  }

  auto &
  operator*() & noexcept
  {
    ASSERT(mHasExpectedValue, "Expected did not have a value");
    return *std::get_if<T>(&val_or_err);
  }

  T &&
  expected(std::string_view errorMessage) &&
  {
    if (is_error()) {
      PANIC(errorMessage);
    }
    return std::move(value());
  }

  template <class Self>
  constexpr auto &&
  value(this Self &&self)
  {
    ASSERT(self.mHasExpectedValue, "Expected did not have a value");
    return std::forward<Self>(std::get<T>(self));
  }

  T &
  value() & noexcept
  {
    ASSERT(mHasExpectedValue, "Expected did not have a value");
    return *std::get_if<T>(&val_or_err);
  }

  T &&
  value() && noexcept
  {
    ASSERT(mHasExpectedValue, "Expected did not have a value");
    return std::get<T>(std::move(val_or_err));
  }

  // Just make it explicit. Easier for everyone to know, we are *definitely* moving out of this value.
  T &&
  take_value() noexcept
  {
    ASSERT(mHasExpectedValue, "Expected did not have a value");
    mHasExpectedValue = false;
    return std::get<T>(std::move(val_or_err));
  }

  const T &
  value() const & noexcept
  {
    ASSERT(mHasExpectedValue, "Expected did not have a value");
    return std::get<T>(val_or_err);
  }

  Err &
  error() & noexcept
  {
    ASSERT(!mHasExpectedValue, "Expected have a value");
    return std::get<Err>(val_or_err);
  }

  Err &&
  take_error() noexcept
  {
    ASSERT(!mHasExpectedValue, "Expected have a value");
    return std::get<Err>(std::move(val_or_err));
  }

  Err &&
  error() && noexcept
  {
    ASSERT(!mHasExpectedValue, "Expected have a value");
    return std::get<Err>(std::move(val_or_err));
  }

  const Err &
  error() const & noexcept
  {
    ASSERT(!mHasExpectedValue, "Expected have a value");
    return std::get<Err>(val_or_err);
  }

  template <typename Transform>
  constexpr auto
  transform(Transform &&fn) && noexcept -> mdb::Expected<FnResult<Transform, T>, Err>
  {
    using Return = FnResult<Transform, T>;
    if (mHasExpectedValue) {
      auto &&res = fn(take_value());
      return mdb::Expected<Return, Err>{res};
    } else {
      return unexpected(take_error());
    }
  }

  template <typename NewErr, typename Transform>
  constexpr auto
  and_then(Transform &&fn) && noexcept -> FnResult<Transform, T>
  {
    if (mHasExpectedValue) {
      return fn(take_value());
    } else {
      return unexpected(NewErr{take_error()});
    }
  }

  constexpr
  operator bool() const noexcept
  {
    return mHasExpectedValue;
  }
};

// auto EXPECT(result, expectedObject);

#define EXPECT_REF(expr, exp)                                                                                     \
  if (!exp) {                                                                                                     \
    return std::move(exp.error());                                                                                \
  }                                                                                                               \
  expr = exp.value();

#define EXPECT(expr, exp)                                                                                         \
  if (!exp) {                                                                                                     \
    return std::move(exp.error());                                                                                \
  }                                                                                                               \
  expr = std::move(exp.value());

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

} // namespace mdb