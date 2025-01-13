/** LICENSE TEMPLATE */
#pragma once

#ifdef MDB_DEBUG
#include <fmt/core.h>
#endif

namespace utils {
template <typename T> class DebugValue
{
public:
#ifdef MDB_DEBUG
  constexpr DebugValue() noexcept = default;
  // non-explicit, because we want something like DebugValue<bool> b = somethingThatProducesBool();
  // or DebugValue<int> dbg = produceCount(); etc
  constexpr DebugValue(const T &debugOnlyValue) noexcept : mValue(debugOnlyValue) {}

  constexpr DebugValue(const DebugValue &other) noexcept = default;
  constexpr DebugValue(DebugValue &&other) noexcept = default;

  constexpr DebugValue &
  operator=(const DebugValue &debugValue)
  {
    if (this == &debugValue) {
      return *this;
    }
    mValue = debugValue.mValue;
    return *this;
  }

  constexpr DebugValue &
  operator=(const T &debugValue)
  {
    mValue = debugValue;
    return *this;
  }

  template <class Self>
  constexpr auto GetValue(this Self&& self) noexcept {
    return self.mValue;
  }

  operator T() {
    return mValue;
  }

private:
  T mValue;
#else
public:
  constexpr DebugValue() noexcept = default;
  // non-explicit, because we want something like DebugValue<bool> b = somethingThatProducesBool();
  // or DebugValue<int> dbg = produceCount(); etc
  constexpr DebugValue(const T &debugOnlyValue) noexcept {}

  constexpr DebugValue(const DebugValue &other) noexcept = default;
  constexpr DebugValue(DebugValue &&other) noexcept = default;

  constexpr DebugValue &
  operator=(const DebugValue &debugValue)
  {
    return *this;
  }

  constexpr DebugValue &
  operator=(const T &debugValue)
  {
    return *this;
  }
#endif
};
} // namespace utils

#ifdef MDB_DEBUG
namespace fmt {
template <typename T> struct formatter<utils::DebugValue<T>>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const utils::DebugValue<T>& debugValue, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "{}", debugValue.GetValue());
  }
};

} // namespace fmt
#endif
