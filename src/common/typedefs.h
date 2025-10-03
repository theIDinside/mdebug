/** LICENSE TEMPLATE */
#pragma once

// stdlib
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <string_view>
#include <tuple>
#include <type_traits>

// system
#include <sys/types.h>

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

template <typename ContainerType>
concept PushBackContainer = requires(ContainerType container) { container.push_back({}); };

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
  char mValue[N];
  static_assert(N > 1,
    "A provided literal of length <= 1, means it's either empty, or it's an empty string with a 0 character. "
    "That's not the intended use.");

  consteval StringLiteral(const char (&str)[N]) noexcept
  {
    for (std::size_t i = 0; i < N; ++i) {
      mValue[i] = str[i];
    }
  }

  template <size_t M, bool RemovePrefix> consteval StringLiteral(StringLiteral<M> string) noexcept
  {
    static_assert(N < M,
      "N > M would not even make sense. It would mean we have trailing null bytes in a constexpr string literal. "
      "We would have absolutely no use for that.");
    constexpr size_t sizeDifference = []() {
      if constexpr (RemovePrefix) {
        return M - N;
      } else {
        return 0;
      }
    }();
    for (auto i = 0; i < N; ++i) {
      mValue[i] = string.mValue[i + sizeDifference];
    }
  }

  static consteval bool
  IsLarger(size_t n) noexcept
  {
    return n >= N - 1;
  }

  consteval char
  operator[](size_t i) const noexcept
  {
    if constexpr (IsLarger(i)) {
      return 0;
    }
    return mValue[i];
  }

  template <size_t StringLength>
  consteval bool
  StartsWith(const char (&string)[StringLength]) const noexcept
  {
    if (N < StringLength) {
      return false;
    }

    const auto sz = string[StringLength - 1] == 0 ? StringLength - 1 : StringLength;
    for (auto i = 0; i < sz; ++i) {
      if (mValue[i] != string[i]) {
        return false;
      }
    }
    return true;
  }

  consteval auto
  RemovePrefix(size_t RemoveBy) noexcept
  {
    return StringLiteral<N - RemoveBy>{ *this };
  }

  consteval const char *
  CString() const
  {
    return mValue;
  }

  consteval std::string_view
  StringView() const
  {
    return std::string_view{ mValue, N - 1 };
  }

  static constexpr auto
  Size() noexcept
  {
    return N - 1;
  }
};

template <> struct StringLiteral<0>
{

  consteval StringLiteral([[maybe_unused]] const char (&str)[0]) noexcept {}

  consteval const char *
  CString() const
  {
    return nullptr;
  }

  consteval std::string_view
  StringView() const
  {
    return std::string_view{};
  }

  static constexpr auto
  Size() noexcept
  {
    return size_t{ 0 };
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

#define KiloBytes(KB) 1024 * KB
#define MegaBytes(MB) 1024 * 1024 * MB

using SessionId = i32;
static constexpr auto kSessionId = std::string_view{ "sessionId" };

namespace mdb::tc {
enum class RunType : u8
{
  Unknown = 0b0000,
  None = Unknown,
  Step,
  Continue,
  SyscallContinue,
};

struct ResumeRequest
{
  RunType mType;
  // The signal to "forward" to the process (if any).
  // Signal == 0, means no signal. This value is passed to ptrace() (and 0 is a valid value, it means no signal
  // there).
  int mSignal;
};

} // namespace mdb::tc