#pragma once
#include <algorithm>
#include <charconv>
#include <concepts>
#include <filesystem>
#include <fmt/core.h>
#include <numeric>
#include <optional>
#include <source_location>
#include <span>
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
    logging::get_logging()->log("mdb", todo_msg);                                                                 \
    logging::get_logging()->on_abort();                                                                           \
    std::terminate(); /** Silence moronic GCC warnings. */                                                        \
    MIDAS_UNREACHABLE                                                                                             \
  }

#define TODO_FMT(fmt_str, ...)                                                                                    \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    const auto todo_msg_hdr =                                                                                     \
        fmt::format("[TODO {}] in {}:{}", loc.function_name(), loc.file_name(), loc.line());                      \
    const auto todo_msg = fmt::format(fmt_str __VA_OPT__(, ) __VA_ARGS__);                                        \
    fmt::println("{}", todo_msg_hdr);                                                                             \
    fmt::println("{}", todo_msg);                                                                                 \
    logging::get_logging()->log("mdb", todo_msg_hdr);                                                             \
    logging::get_logging()->log("mdb", todo_msg);                                                                 \
    logging::get_logging()->on_abort();                                                                           \
    std::terminate(); /** Silence moronic GCC warnings. */                                                        \
    MIDAS_UNREACHABLE                                                                                             \
  }

// Identical to ASSERT, but doesn't care about build type
#define VERIFY(cond, msg, ...)                                                                                    \
  {                                                                                                               \
    std::source_location loc = std::source_location::current();                                                   \
    if (!(cond)) {                                                                                                \
      panic(fmt::format("{} FAILED {}", #cond, fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)), loc, 1);             \
    }                                                                                                             \
  }

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

template <typename T> class TraceePointer
{
public:
  using Type = typename std::remove_cv_t<T>;
  constexpr TraceePointer() noexcept : remote_addr{0} {}
  constexpr TraceePointer(std::nullptr_t) noexcept : remote_addr{0} {}
  constexpr TraceePointer &operator=(const TraceePointer &) = default;
  constexpr TraceePointer(const TraceePointer &) = default;
  constexpr TraceePointer(TraceePointer &&) = default;
  constexpr operator std::uintptr_t() const { return get(); }
  constexpr TraceePointer(std::uintptr_t addr) noexcept : remote_addr(addr) {}
  constexpr TraceePointer(T *t) noexcept : remote_addr(reinterpret_cast<std::uintptr_t>(t)) {}
  constexpr ~TraceePointer() = default;

  // Utility function. When one needs to be sure we are offseting by *bytes* and not by sizeof(T) * n.
  friend TraceePointer<T> constexpr offset(TraceePointer<T> ptr, unsigned long long bytes) noexcept
  {
    return ptr.remote_addr + bytes;
  }

  // `offset` is in N of T, not in bytes (unless T, of course, is a byte-like type)
  template <std::integral OffsetT>
  constexpr TraceePointer
  operator+(OffsetT offset) const noexcept
  {
    const auto res = remote_addr + (offset * type_size());
    return TraceePointer{res};
  }

  // `offset` is in N of T, not in bytes (unless T, of course, is a byte-like type)
  template <std::integral OffsetT>
  constexpr TraceePointer
  operator-(OffsetT offset) const noexcept
  {
    const auto res = remote_addr - (offset * type_size());
    return TraceePointer{res};
  }

  template <std::integral OffsetT>
  constexpr TraceePointer &
  operator+=(OffsetT offset) noexcept
  {
    remote_addr += (offset * type_size());
    return *this;
  }

  template <std::integral OffsetT>
  constexpr TraceePointer &
  operator-=(OffsetT offset) noexcept
  {
    remote_addr -= (offset * type_size());
    return *this;
  }

  constexpr TraceePointer &
  operator++() noexcept
  {
    remote_addr += type_size();
    return *this;
  }

  constexpr TraceePointer
  operator++(int) noexcept
  {
    const auto current = remote_addr;
    remote_addr += type_size();
    return TraceePointer{current};
  }

  constexpr TraceePointer &
  operator--() noexcept
  {
    remote_addr -= type_size();
    return *this;
  }

  constexpr TraceePointer
  operator--(int) noexcept
  {
    const auto current = remote_addr;
    remote_addr -= type_size();
    return TraceePointer{current};
  }

  uintptr_t
  get() const noexcept
  {
    return remote_addr;
  }

  // Returns the size of the pointed-to type so we can do pointer arithmetics on it.
  // We handle the edge case of void pointers, by assuming an Architecture's "word size" (32-bit/64-bit)
  static constexpr unsigned long long
  type_size() noexcept
  {
    if constexpr (std::is_void_v<T>)
      return 1;
    else
      return sizeof(T);
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

  constexpr auto
  to_string() const noexcept -> std::string
  {
    std::string buffer{};
    buffer.reserve(20);
    fmt::format_to(std::back_inserter(buffer), "0x{:x}", get());
    return buffer;
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
  std::uintptr_t remote_addr;
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
  if (Value value; std::from_chars(s.data(), s.data() + s.size(), value).ec == std::errc{})
    return value;
  else
    return std::nullopt;
}

Option<AddrPtr> to_addr(std::string_view s) noexcept;

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
    if (p(*it, item))
      return it;
  }
  return std::cend(vec);
}

template <typename U, typename T, typename Predicate, typename Transform>
constexpr auto
map(std::vector<T> &vec, Predicate &&p, Transform &&transform) noexcept -> std::optional<U>
{
  for (auto it = std::cbegin(vec); it != std::end(vec); ++it) {
    if (p(*it))
      return transform(*it);
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

enum class RegDescriptor : unsigned char
{
#define REGISTER(Name, Value) Name = Value,
#define REG_DESC
#include "./defs/registers.defs"
#undef REG_DESC
#undef REGISTER
};

#define REGISTER(Name, Value)                                                                                     \
  case Name:                                                                                                      \
    return #Name;
static constexpr std::string_view
reg_name(RegDescriptor reg) noexcept
{
  using enum RegDescriptor;
  switch (reg) {
#define REG_DESC
#include "./defs/registers.defs"
#undef REG_DESC
  }
}
#undef REGISTER