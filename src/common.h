/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/macros.h>

// stdlib
#include <algorithm>
#include <bit>
#include <charconv>
#include <concepts>
#include <filesystem>
#include <numeric>
#include <optional>
#include <source_location>

// system

#include <sys/mman.h>
#include <sys/user.h>
#include <type_traits>
#include <vector>

// dependecy

namespace mdb {

namespace fs = std::filesystem;
using Path = fs::path;

using Tid = pid_t;
using Pid = pid_t;

struct LWP
{
  Pid pid;
  Tid tid;

  constexpr bool operator<=>(const LWP &other) const = default;
};

template <typename, typename = void> struct has_begin : std::false_type
{
};

template <typename T> struct has_begin<T, std::void_t<decltype(std::begin(std::declval<T>()))>> : std::true_type
{
};

template <typename, typename = void> struct has_end : std::false_type
{
};

template <typename T> struct has_end<T, std::void_t<decltype(std::end(std::declval<T>()))>> : std::true_type
{
};

template <typename T> struct is_unique_ptr : std::false_type
{
};

template <typename T> struct is_unique_ptr<std::unique_ptr<T>> : std::true_type
{
};

template <typename T> struct is_shared_ptr : std::false_type
{
};

template <typename T> struct is_shared_ptr<std::shared_ptr<T>> : std::true_type
{
};

template <typename T> concept IsSmartPointer = is_unique_ptr<T>::value || is_shared_ptr<T>::value;
template <typename T> concept IsRange = has_begin<T>::value && has_end<T>::value;

// A line/col-source coordinate. Identifies a source file by full path and a line and column number
struct SourceCoordinate
{
  std::string path;
  std::uint32_t line;
  std::uint32_t column;
};

struct SourceCoordinateRef
{
  std::string_view path;
  std::uint32_t line;
  std::uint32_t column;
};

template <typename T> using SharedPtr = std::shared_ptr<T>;
template <typename T> using UniquePtr = std::unique_ptr<T>;

enum class DwFormat : std::uint8_t
{
  DW32,
  DW64
};

#define MDB_PAGE_SIZE 4096

template <typename T> using Option = std::optional<T>;

enum class TargetSession
{
  Launched,
  Attached
};

// "remove_cvref_t" is an absolutely retarded name. We therefore call it `ActualType<T>` to signal clear intent.
template <typename T> using ActualType = std::remove_cvref_t<T>;

template <class... T> constexpr bool always_false = false;

[[noreturn]] void panic(
  std::string_view err_msg, const char *functionName, const char *file, int line, int strip_levels = 0);
[[noreturn]] void panic(std::string_view err_msg, const std::source_location &loc_msg, int strip_levels = 0);

/**
 * Get name for `syscall_number`
 */
std::string_view syscall_name(unsigned long long syscall_number);

#define MUST_HOLD(cond, msg)                                                                                      \
  if (!(cond)) [[unlikely]] {                                                                                     \
    const std::source_location loc = std::source_location::current();                                             \
    mdb::panic(std::format("{}: assertion failed: {}", msg, #cond),                                               \
      loc.function_name(),                                                                                        \
      loc.file_name(),                                                                                            \
      loc.line() - 2,                                                                                             \
      3);                                                                                                         \
  }

// clang-format off
// VERIFY does what ASSERT does but regardless of build type. Is expected to uphold hard invariants.
#define VERIFY(cond, msg, ...) if (!(cond)) [[unlikely]] { std::source_location loc = std::source_location::current(); \
    mdb::panic(std::format("{} FAILED {}", #cond, std::format(msg __VA_OPT__(, ) __VA_ARGS__)), loc, 1);               \
  }
// clang-format on
#if defined(MDB_DEBUG) and MDB_DEBUG == 1
#define MDB_ASSERT(cond, msg, ...) VERIFY(cond, msg, __VA_ARGS__)
/* A macro that asserts on failure in debug mode, but also actually performs the (op) in release. */
#define PERFORM_ASSERT(op, msg, ...) VERIFY((op), msg, __VA_ARGS__)

#define MDB_ASSERT_IF(ONLYWHEN, cond, ...)                                                                        \
  if ((ONLYWHEN))                                                                                                 \
  MDB_ASSERT(cond, __VA_ARGS__)

#else
#define MDB_ASSERT(cond, msg, ...) VERIFY(cond, msg, __VA_ARGS__)
#define MDB_ASSERT_IF(ONLYWHEN, cond, ...)
#define PERFORM_ASSERT(op, msg, ...) op
#endif

#if defined(MDB_DEBUG) and MDB_DEBUG == 1
#define DBG(x) x
#else
#define DBG(x)
#endif

template <typename T>
T *
mmap_buffer(unsigned long long size) noexcept
{
  auto ptr = (T *)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  MDB_ASSERT(ptr != MAP_FAILED, "Failed to mmap buffer of size {}", size);
  return ptr;
}

template <std::integral Value>
constexpr Option<Value>
to_integral(std::string_view s)
{
  if (Value value; std::from_chars(s.data(), s.data() + s.size(), value).ec == std::errc{}) {
    return value;
  } else {
    return std::nullopt;
  }
}

template <typename Container>
void
keep_range(Container &c, unsigned long start_idx, unsigned long end_idx) noexcept
{
  MDB_ASSERT(start_idx <= end_idx, "Invalid parameters start {} end {}", start_idx, end_idx);
  const auto start = c.begin() + start_idx;
  const auto end = c.begin() + std::min(end_idx, c.size());
  // erase from end to c.end() first to keep iterators valid
  c.erase(end, c.end());
  c.erase(c.begin(), start);
}

enum class X86Register : u8
{
#define REG(Name, Value) Name = Value,
#define REG_DESC
#include "./defs/registers.defs"
#undef REG_DESC
#undef REG
};

static constexpr std::string_view
reg_name(X86Register reg) noexcept
{
  using enum X86Register;
  switch (reg) {
#define REG_DESC
#define REG(Name, Value)                                                                                          \
  case Name:                                                                                                      \
    return #Name;
#include "./defs/registers.defs"
#undef REG
#undef REG_DESC
  }
}

template <typename... Ts> struct Match : Ts...
{
  using Ts::operator()...;
};
template <class... Ts> Match(Ts...) -> Match<Ts...>;

#if defined(__clang__)
#ifndef COMPILERUSED
#define COMPILERUSED clang
#endif
#elif defined(__GNUC__) || defined(__GNUG__)
#ifndef COMPILERUSED_GCC
#define COMPILERUSED_GCC
#endif
#endif

template <typename T>
constexpr bool
IsAligned(void *ptr)
{
  return (std::bit_cast<uintptr_t>(ptr) % sizeof(T)) == 0;
}

} // namespace mdb