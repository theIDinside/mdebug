/** LICENSE TEMPLATE */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <string_view>
#include <sys/types.h>
#include <tuple>
#include <type_traits>

using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u16 = std::uint16_t;
using u8 = std::uint8_t;

using i64 = std::int64_t;
using i32 = std::int32_t;
using i16 = std::int16_t;
using i8 = std::int8_t;

using f32 = float;
using f64 = double;

using Tid = pid_t;
using Pid = pid_t;

using Allocator = std::pmr::polymorphic_allocator<>;

template <typename Fn, typename... FnArgs> using FnResult = std::invoke_result_t<Fn, FnArgs...>;

template <typename T> struct IsTemplateType : std::false_type
{
};

template <template <typename...> class TemplatedType, typename... Args>
struct IsTemplateType<TemplatedType<Args...>> : std::true_type
{
};

template <typename T> static inline constexpr bool IsTemplate = IsTemplateType<T>::value;

// String literal wrapper for use in template parameters
// Template type for string literals
template <std::size_t N> struct StringLiteral
{
  consteval StringLiteral() = default;

  consteval StringLiteral(const char (&str)[N]) noexcept
  {
    for (std::size_t i = 0; i < N; ++i) {
      value[i] = str[i];
    }
  }

  char value[N];

  consteval const char *
  CString() const
  {
    return value;
  }

  consteval std::string_view
  StringView() const
  {
    return std::string_view{value, N};
  }
};

template <typename... Args> struct ReturnType;

// Specialization for non-empty packs
template <typename First, typename... Rest> struct ReturnType<First, Rest...>
{
  using Type = First; // The first type in the parameter pack
};

// Helper to convert TypeList to std::function
template <typename Tuple> struct ToFunction;

template <typename ReturnType, typename... Args> struct ToFunction<std::tuple<ReturnType, Args...>>
{
  using FunctionType = std::function<ReturnType(Args...)>;
  using Return = ReturnType;
  using FnArgs = std::tuple<Args...>;
  static constexpr inline auto ArgSize = std::tuple_size_v<FnArgs>;
};