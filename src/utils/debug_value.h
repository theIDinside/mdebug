/** LICENSE TEMPLATE */
#pragma once

#include "common/formatter.h"
namespace mdb {
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
  constexpr auto
  GetValue(this Self &&self) noexcept
  {
    return self.mValue;
  }

  operator T() { return mValue; }

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
} // namespace mdb

#ifdef MDB_DEBUG
template <typename T> struct std::formatter<mdb::DebugValue<T>>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const mdb::DebugValue<T> &debugValue, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(), "{}", debugValue.GetValue());
  }
};

#endif
