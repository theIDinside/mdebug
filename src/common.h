#pragma once
#include <algorithm>
#include <charconv>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fmt/core.h>
#include <optional>
#include <source_location>
#include <span>
#include <sys/mman.h>
#include <sys/user.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <utils/logger.h>
#include <utils/macros.h>
#include <variant>
#include <vector>

using perfclock = std::chrono::high_resolution_clock;

namespace fs = std::filesystem;
using Path = fs::path;

using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u16 = std::uint16_t;
using u8 = std::uint8_t;

using i64 = std::int64_t;
using i32 = std::int32_t;
using i16 = std::int16_t;
using i8 = std::int8_t;

using Tid = pid_t;
using Pid = pid_t;

template <typename T> using SharedPtr = std::shared_ptr<T>;
template <typename T> using UniquePtr = std::unique_ptr<T>;

enum class DwFormat : std::uint8_t
{
  DW32,
  DW64
};

struct InitLength
{
  DwFormat format;
  u64 length;
};

template <typename TimeStamp>
constexpr u64
nanos(TimeStamp a, TimeStamp b)
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count();
}

template <typename TimeStamp>
constexpr u64
micros(TimeStamp a, TimeStamp b)
{
  return std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
}

#define MDB_PAGE_SIZE 4096

template <typename T> using Option = std::optional<T>;

enum class TargetSession
{
  Launched,
  Attached
};

// "remove_cvref_t" is an absolutely retarded name. We therefore call it `ActualType<T>` to signal clear intent.
template <typename T> using ActualType = std::remove_cvref_t<T>;

struct DataBlock
{
  const u8 *const ptr;
  u64 size;
};

std::span<const u8> as_span(DataBlock block) noexcept;

template <class... T> constexpr bool always_false = false;
template <size_t... T> constexpr bool always_false_i = false;

#define NO_COPY(CLASS)                                                                                            \
  CLASS(const CLASS &) = delete;                                                                                  \
  CLASS(CLASS &) = delete;                                                                                        \
  CLASS &operator=(CLASS &) = delete;                                                                             \
  CLASS &operator=(const CLASS &) = delete;

[[noreturn]] void panic(std::string_view err_msg, const std::source_location &loc_msg, int strip_levels = 0);

/**
 * . syscall_number - the fucking param
 */
std::string_view syscall_name(u64 syscall_number);

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

  // Utility function. When one needs to be sure we are offseting by *bytes* and not by sizeof(T) * n.
  friend TraceePointer<T> constexpr offset(TraceePointer<T> ptr, u64 bytes) noexcept
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
  static constexpr u64
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

struct UnrelocatedTraceePointer : public TraceePointer<void>
{
  TraceePointer
  relocate(std::uintptr_t offset) noexcept
  {
    return TraceePointer<void>{this->get() + offset};
  }
};

using AddrPtr = TraceePointer<void>;
template <typename T> using TPtr = TraceePointer<T>;

static constexpr u8 LEB128_MASK = 0b0111'1111;

template <typename T> struct LEB128
{
  T result;
  u8 *advanced;
};

template <typename T> concept IsBitsType = std::integral<T> || std::is_enum_v<T> || std::is_scoped_enum_v<T>;

/* Holds the decoded value of a ULEB/LEB128 as well as the length of the decoded data (in bytes). */
template <IsBitsType T> struct LEB128Read
{
  T result;
  u8 bytes_read;
};

const u8 *
decode_uleb128(const u8 *data, IsBitsType auto &value) noexcept
{
  u64 res = 0;
  u64 shift = 0;
  u8 index = 0;
  for (;;) {
    u8 byte = data[index];
    res |= ((byte & LEB128_MASK) << shift);
    ASSERT(!(shift == 63 && byte != 0x0 && byte != 0x1), "Decoding of ULEB128 failed at index {}", index);
    ++index;
    if ((byte & ~LEB128_MASK) == 0) {
      // We don't want C++ to set a "good" enum value
      // if `value` is of type enum. We literally want a bit blast here (and we rely on that being the case)
      std::memcpy(&value, &res, sizeof(decltype(value)));
      return data + index;
    }
    shift += 7;
  }
}

const u8 *
decode_leb128(const u8 *data, IsBitsType auto &value) noexcept
{
  i64 res = 0;
  u64 shift = 0;
  u8 index = 0;
  u64 size = 64;
  u8 byte;
  for (;;) {
    byte = data[index];
    ASSERT(!(shift == 63 && byte != 0x0 && byte != 0x7f), "Decoding of LEB128 failed at index {}", index);
    res |= ((byte & LEB128_MASK) << shift);
    shift += 7;
    ++index;
    if ((byte & ~LEB128_MASK) == 0)
      break;
  }
  if (shift < size && (byte & 0x40)) {
    res |= ((-1) << shift);
  }
  // We don't want C++ to set a "good" enum value
  // if `value` is of type enum. We literally want a bit blast here (and we rely on that being the case)
  std::memcpy(&value, &res, sizeof(decltype(value)));
  return data + index;
}
// clang-format off
template <typename BufferType>
concept ByteContainer = requires(BufferType t) {
  { t.size() } -> std::convertible_to<u64>;
  { t.begin() } -> std::convertible_to<const u8 *>;
  { t.end() } -> std::convertible_to<const u8 *>;
  { t.offset(10) } -> std::convertible_to<const u8 *>;
};
// clang-format on

// clang-format off
template <typename ByteType>
concept ByteCode = requires(ByteType bt) {
  { std::to_underlying(bt) } -> std::convertible_to<u8>;
} && std::is_enum<ByteType>::value;
// clang-format on

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
mmap_buffer(u64 size) noexcept
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

template <typename Container>
void
keep_range(Container &c, u64 start_idx, u64 end_idx) noexcept
{
  ASSERT(start_idx <= end_idx, "Invalid parameters start {} end {}", start_idx, end_idx);
  const auto start = c.begin() + start_idx;
  const auto end = c.begin() + std::min(end_idx, c.size());
  // erase from end to c.end() first to keep iterators valid
  c.erase(end, c.end());
  c.erase(c.begin(), start);
}

enum class RegDescriptor : u8
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
static constexpr u16 offsets[17] = {
    offsetof(user_regs_struct, rax), offsetof(user_regs_struct, rdx), offsetof(user_regs_struct, rcx),
    offsetof(user_regs_struct, rbx), offsetof(user_regs_struct, rsi), offsetof(user_regs_struct, rdi),
    offsetof(user_regs_struct, rbp), offsetof(user_regs_struct, rsp), offsetof(user_regs_struct, r8),
    offsetof(user_regs_struct, r9),  offsetof(user_regs_struct, r10), offsetof(user_regs_struct, r11),
    offsetof(user_regs_struct, r12), offsetof(user_regs_struct, r13), offsetof(user_regs_struct, r14),
    offsetof(user_regs_struct, r15), offsetof(user_regs_struct, rip)};

static constexpr std::string_view reg_names[17] = {"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8",
                                                   "r9",  "r10", "r11", "r12", "r13", "r14", "r15", "rip"};

u64 get_register(user_regs_struct *regs, int reg_number) noexcept;

static constexpr auto X86_64_RIP_REGISTER = 16;

template <typename T, typename U, typename Fn, typename R = typename std::invoke_result_t<Fn, T, U>>
std::optional<R>
zip(const std::optional<T> &l, const std::optional<U> &r, Fn &&fn)
{
  if (l && r)
    return std::optional<R>{fn(*l, *r)};
  else
    return std::nullopt;
}

template <typename T> struct SearchResult
{
  // found element in container that was searched.
  const T *ptr;
  // index in the container `ptr` was found in
  u32 index;
  // capacity of the container `ptr` was found in
  u32 cap;

  constexpr bool
  found() const noexcept
  {
    return ptr != nullptr;
  }
};

template <typename DeferFn> class ScopedDefer
{
public:
  explicit ScopedDefer(DeferFn &&fn) noexcept : defer_fn(std::move(fn)) {}
  ~ScopedDefer() noexcept { defer_fn(); }

private:
  DeferFn defer_fn;
};

template <typename T>
constexpr std::optional<T>
take(std::optional<T> &&value) noexcept
{
  if (!value)
    return std::nullopt;
  auto v = value.value();
  value.reset();
  return v;
}

using SecString = std::string_view;
using CString = const char *;