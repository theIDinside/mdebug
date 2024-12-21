#pragma once
#include <algorithm>
#include <charconv>
#include <concepts>
#include <filesystem>
#include <fmt/core.h>
#include <numeric>
#include <optional>
#include <source_location>
#include <sys/mman.h>
#include <sys/user.h>
#include <type_traits>
#include <utils/logger.h>
#include <utils/macros.h>
#include <variant>
#include <vector>

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
  SourceCoordinate(std::string path, u32 line, u32 col = 0) noexcept;
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

[[noreturn]] void panic(std::string_view err_msg, const char *functionName, const char *file, int line,
                        int strip_levels = 0);
[[noreturn]] void panic(std::string_view err_msg, const std::source_location &loc_msg, int strip_levels = 0);

/**
 * Get name for `syscall_number`
 */
std::string_view syscall_name(unsigned long long syscall_number);

#define PANIC(err_msg)                                                                                            \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    panic(err_msg, loc, 1);                                                                                       \
  }

#define TODO(abort_msg)                                                                                           \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    const auto todo_msg = fmt::format("[TODO]: {}\nin {}:{}", abort_msg, loc.file_name(), loc.line());            \
    fmt::println("{}", todo_msg);                                                                                 \
    logging::get_logging()->log(logging::Channel::core, todo_msg);                                                \
    logging::get_logging()->on_abort();                                                                           \
    std::terminate(); /** Silence moronic GCC warnings. */                                                        \
    MIDAS_UNREACHABLE                                                                                             \
  }

#define IGNORE_WARN(...) (void)sizeof...(__VA_ARGS__);

template <typename... Args>
void
IgnoreArgs(const Args&...)
{
}

#define TODO_IGNORE_WARN(message, ...)                                                                            \
  IgnoreArgs(__VA_ARGS__);                                                                                        \
  TODO(message);

#define TODO_FMT(fmt_str, ...)                                                                                    \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    const auto todo_msg_hdr =                                                                                     \
      fmt::format("[TODO {}] in {}:{}", loc.function_name(), loc.file_name(), loc.line());                        \
    const auto todo_msg = fmt::format(fmt_str __VA_OPT__(, ) __VA_ARGS__);                                        \
    fmt::println("{}", todo_msg_hdr);                                                                             \
    fmt::println("{}", todo_msg);                                                                                 \
    logging::get_logging()->log(logging::Channel::core, todo_msg_hdr);                                            \
    logging::get_logging()->log(logging::Channel::core, todo_msg);                                                \
    logging::get_logging()->on_abort();                                                                           \
    std::terminate(); /** Silence moronic GCC warnings. */                                                        \
    MIDAS_UNREACHABLE                                                                                             \
  }

#define MUST_HOLD(cond, msg)                                                                                      \
  if (!(cond)) [[unlikely]] {                                                                                     \
    const std::source_location loc = std::source_location::current();                                             \
    panic(fmt::format("{}: assertion failed: {}", msg, #cond), loc.function_name(), loc.file_name(),              \
          loc.line() - 2, 3);                                                                                     \
  }

// clang-format off
// Identical to ASSERT, but doesn't care about build type
#define VERIFY(cond, msg, ...) if (!(cond)) [[unlikely]] { std::source_location loc = std::source_location::current(); \
    panic(fmt::format("{} FAILED {}", #cond, fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)), loc, 1);               \
  }
// clang-format on
#if defined(MDB_DEBUG) and MDB_DEBUG == 1
#define ASSERT(cond, msg, ...) VERIFY(cond, msg, __VA_ARGS__)
/* A macro that asserts on failure in debug mode, but also actually performs the (op) in release. */
#define PERFORM_ASSERT(op, msg, ...) VERIFY((op), msg, __VA_ARGS__)
#else
#define ASSERT(cond, msg, ...)
#define PERFORM_ASSERT(op, msg, ...) op
#endif

#if defined(MDB_DEBUG) and MDB_DEBUG == 1
#define DBG(x) x
#else
#define DBG(x)
#endif

template <typename T, typename... Args>
constexpr const T *
unwrap(const std::variant<Args...> &variant) noexcept
{
  const T *r = nullptr;
  std::visit(
    [&r](auto &&item) {
      using var_t = ActualType<decltype(item)>;
      if constexpr (std::is_same_v<var_t, T>) {
        r = &item;
      } else {
        PANIC("Unexpected type in variant");
      }
    },
    variant);
  return r;
}

template <typename T, typename... Args>
constexpr const T *
maybe_unwrap(const std::variant<Args...> &variant) noexcept
{
  const T *r = nullptr;
  std::visit(
    [&r](auto &&item) {
      using var_t = ActualType<decltype(item)>;
      if constexpr (std::is_same_v<var_t, T>) {
        r = &item;
      } else {
        r = nullptr;
      }
    },
    variant);
  return r;
}

template <typename T>
T *
mmap_buffer(unsigned long long size) noexcept
{
  auto ptr = (T *)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT(ptr != MAP_FAILED, "Failed to mmap buffer of size {}", size);
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

template <typename T, typename Predicate>
constexpr bool
any_of(const std::vector<T> &vec, Predicate &&p) noexcept
{
  return std::any_of(vec.cbegin(), vec.cend(), p);
}

template <typename T, typename Predicate>
constexpr auto
find(const std::vector<T> &vec, Predicate &&p) noexcept
{
  return std::find_if(vec.cbegin(), vec.cend(), p);
}

template <typename T, typename Predicate>
constexpr auto
find(std::vector<T> &vec, Predicate &&p) noexcept
{
  return std::find_if(vec.begin(), vec.end(), p);
}

template <typename T, typename Predicate>
constexpr auto
find(std::vector<T> &vec, const T &item, Predicate &&p) noexcept
{
  for (auto it = std::cbegin(vec); it != std::end(vec); ++it) {
    if (p(*it, item)) {
      return it;
    }
  }
  return std::cend(vec);
}

template <typename U, typename T, typename Predicate, typename Transform>
constexpr auto
map(std::vector<T> &vec, Predicate &&p, Transform &&transform) noexcept -> std::optional<U>
{
  for (auto it = std::cbegin(vec); it != std::end(vec); ++it) {
    if (p(*it)) {
      return transform(*it);
    }
  }
  return std::nullopt;
}

constexpr auto
accumulate(const auto &container, auto &&init, auto &&fn) noexcept
{
  return std::accumulate(container.cbegin(), container.cend(), init, fn);
}

template <typename T, typename Fn>
constexpr auto
ptr_and_then(T *t, Fn &&f)
{
  using RetType = decltype(f(*t));
  if (t != nullptr) {
    return f(*t);
  } else {
    return RetType{};
  }
}

template <typename Container>
void
keep_range(Container &c, unsigned long start_idx, unsigned long end_idx) noexcept
{
  ASSERT(start_idx <= end_idx, "Invalid parameters start {} end {}", start_idx, end_idx);
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
#define COMPILERUSED clang
#elif defined(__GNUC__) || defined(__GNUG__)
#define COMPILERUSED_GCC
#endif
