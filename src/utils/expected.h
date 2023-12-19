#pragma once
#include <memory>
#include <type_traits>
#include <utility>
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

template <typename T, typename Err> class Expected
{
  union
  {
    Err err;
    T val;
  };
  bool has_value;

  friend auto unexpected(Err &&) noexcept;
  friend auto unexpected(const Err &) noexcept;

public:
  // template <typename... Args> Expected(Args... args) noexcept : val(std::forward<Args>(args)...) {}

  Expected(T t) noexcept
    requires(!std::is_trivially_destructible_v<T>)
      : val(std::move(t)), has_value(true)
  {
  }

  Expected(T t) noexcept
    requires(std::is_trivially_destructible_v<T>)
      : val(t), has_value(true)
  {
  }

  template <typename... Args> Expected(Args... args) noexcept : val(std::forward<Args>(args)...), has_value(true)
  {
  }

  Expected(Err &&e) noexcept : err(std::move(e)), has_value(false) {}
  Expected(const Err &e) noexcept : err(e), has_value(false) {}

  Expected(const Unexpected<Err> &conv) : err(conv.err), has_value(false) {}
  Expected(Unexpected<Err> &&conv) : err(std::move(conv.err)), has_value(false) {}

  ~Expected() noexcept
    requires(trivial_destruct<T>() && trivial_destruct<Err>())
  = default;

  ~Expected() noexcept
    requires(!trivial_destruct<T>() && trivial_destruct<Err>())
  {
    if (has_value) {
      if constexpr (std::is_array_v<T>) {
        std::destroy(val, val + std::size(val));
      } else {
        std::destroy_at(&val);
      }
    }
  }

  ~Expected() noexcept
    requires(trivial_destruct<T>() && !trivial_destruct<Err>())
  {
    if (!has_value) {
      if constexpr (std::is_array_v<Err>) {
        std::destroy(err, err + std::size(err));
      } else {
        std::destroy_at(&err);
      }
    }
  }

  ~Expected() noexcept
    requires(!trivial_destruct<T>() && !trivial_destruct<Err>())
  {
    if (has_value) {
      if constexpr (std::is_array_v<T>) {
        std::destroy(val, val + std::size(val));
      } else {
        std::destroy_at(&val);
      }
    } else {
      if constexpr (std::is_array_v<Err>) {
        std::destroy(err, err + std::size(err));
      } else {
        std::destroy_at(&err);
      }
    }
  }

  constexpr bool
  is_expected() const noexcept
  {
    return has_value;
  }

  std::enable_if<std::is_pointer<T>::value, T *>
  operator->() noexcept
  {
    return val;
  }

  auto &&
  operator*() && noexcept
  {
    return val;
  }

  auto &
  operator*() & noexcept
  {
    return val;
  }

  T &
  value() & noexcept
  {
    return val;
  }

  T &&
  value() && noexcept
  {
    return std::move(val);
  }

  const T &
  value() const & noexcept
  {
    return val;
  }

  Err &
  error() & noexcept
  {
    return err;
  }

  Err &&
  error() && noexcept
  {
    return err;
  }

  const Err &
  error() const & noexcept
  {
    return err;
  }
};
} // namespace utils