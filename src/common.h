#pragma once

#include "lib/lockguard.h"
#include "lib/spinlock.h"
#include <algorithm>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <execinfo.h>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <optional>
#include <source_location>
#include <span>
#include <sys/mman.h>
#include <sys/poll.h>
#include <type_traits>
#include <unistd.h>
#include <variant>
#include <vector>

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

#define PAGE_SIZE 4096

template <typename T> using Option = std::optional<T>;

/** C++-ified result from waitpid syscall. */
struct WaitPid
{
  Tid tid;
  int status;
};

enum class TargetSession
{
  Launched,
  Attached
};

/** `wait`'s for `tid` in a non-blocking way and also if the operation returns a result, leaves the wait value in
 * place so that `wait` can be called again to reap it. If no child was waited on returns `none`. */
Option<WaitPid> waitpid_peek(pid_t tid) noexcept;
/** `wait`'s for `tid` in a non-blocking way. If waiting on `tid` yielded no wait status, returns `none` */
Option<WaitPid> waitpid_nonblock(pid_t tid) noexcept;

Option<WaitPid> waitpid_block(pid_t tid) noexcept;

// "remove_cvref_t" is an absolutely retarded name. We therefore call it `ActualType<T>` to signal clear intent.
template <typename T> using ActualType = std::remove_cvref_t<T>;

struct DataBlock
{
  const u8 *const ptr;
  u64 size;
};

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
    fmt::println("[TODO {}] in {}:{} - {}", loc.function_name(), loc.file_name(), loc.line(), abort_msg);         \
    std::terminate();                                                                                             \
  }

// Identical to ASSERT, but doesn't care about build type
#define VERIFY(cond, msg, ...)                                                                                    \
  {                                                                                                               \
    std::source_location loc = std::source_location::current();                                                   \
    if (!(cond)) {                                                                                                \
      panic(fmt::format("{} FAILED {}", #cond, fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)), loc, 1);             \
    }                                                                                                             \
  }

#if defined(MDB_DEBUG)
#define ASSERT(cond, msg, ...) VERIFY(cond, msg, __VA_ARGS__)
#else
#define ASSERT(cond, msg, ...)
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

  template <typename U>
  friend bool
  operator<=>(const TraceePointer<T> &l, const TraceePointer<U> &r) noexcept
  {
    return l.get() <=> r.get();
  }

  constexpr auto
  to_string() const noexcept -> std::string
  {
    std::string buffer{};
    buffer.reserve(20);
    fmt::format_to(std::back_inserter(buffer), "0x{:x}", get());
    return buffer;
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
  format(TraceePointer<T> const &tptr, FormatContext &ctx)
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

class ScopedFd
{
public:
  ScopedFd() noexcept : fd(-1), p{} {}
  ScopedFd(int fd) noexcept;
  ScopedFd(int fd, Path p) noexcept;
  ~ScopedFd() noexcept;

  ScopedFd &
  operator=(ScopedFd &&other) noexcept
  {
    if (this == &other)
      return *this;
    close();
    fd = other.fd;
    p = std::move(other.p);
    file_size_ = other.file_size_;
    other.fd = -1;
    return *this;
  }

  ScopedFd(ScopedFd &&) noexcept;

  int get() const noexcept;
  bool is_open() const noexcept;
  void close() noexcept;
  operator int() const noexcept;
  u64 file_size() const noexcept;
  const Path &path() const noexcept;
  void forget() noexcept;

  static ScopedFd open(const Path &p, int flags, mode_t mode = mode_t{0}) noexcept;
  static ScopedFd open_read_only(const Path &p) noexcept;
  static ScopedFd take_ownership(int fd) noexcept;

private:
  int fd;
  Path p;
  u64 file_size_;
};

constexpr pollfd
cfg_read_poll(int fd, int additional_flags) noexcept
{
  pollfd pfd{0, 0, 0};
  pfd.events = POLLIN | additional_flags;
  pfd.fd = fd;
  return pfd;
}

constexpr pollfd
cfg_write_poll(int fd, int additional_flags) noexcept
{
  pollfd pfd{0, 0, 0};
  pfd.events = POLLOUT | additional_flags;
  pfd.fd = fd;
  return pfd;
}

static constexpr u8 LEB128_MASK = 0b0111'1111;

template <typename T> struct LEB128
{
  T result;
  u8 *advanced;
};

template <typename T> concept IsBitsType = std::integral<T> || std::is_enum_v<T> || std::is_scoped_enum_v<T>;

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
  { t.data() } -> std::convertible_to<u8 *>;
  { t.offset(10) } -> std::convertible_to<u8 *>;
};
// clang-format on

class DwarfBinaryReader
{
public:
  enum class InitLengthRead
  {
    UpdateBufferSize,
    Ignore
  };

  using enum InitLengthRead;

  DwarfBinaryReader(const u8 *buffer, u64 size) noexcept;
  DwarfBinaryReader(const DwarfBinaryReader &reader) noexcept;

  template <ByteContainer BC> DwarfBinaryReader(const BC &bc) : buffer(bc.data()), head(bc.data()), size(bc.size())
  {
  }

  template <ByteContainer BC>
  DwarfBinaryReader(const BC &bc, u64 offset)
      : buffer(bc.offset(offset)), head(bc.offset(offset)), size(bc.size() - offset)
  {
  }

  template <typename T>
    requires(!std::is_pointer_v<T>)
  constexpr T read_value() noexcept
  {
    ASSERT(remaining_size() >= sizeof(T),
           "Buffer has not enough data left to read value of size {} (bytes left={})", sizeof(T),
           remaining_size());
    using Type = typename std::remove_cv_t<T>;
    constexpr auto sz = sizeof(Type);
    Type value = *(Type *)head;
    head += sz;
    return value;
  }

  template <typename T, size_t N>
  constexpr void
  read_into_array(std::array<T, N> &out)
  {
    for (auto &elem : out) {
      elem = read_value<T>();
    }
  }

  template <typename T>
  T
  peek_value() noexcept
  {
    return *(T *)head;
  }

  template <InitLengthRead InitReadAction>
  u64
  read_initial_length() noexcept
  {
    u32 peeked = peek_value<u32>();
    if (peeked != 0xff'ff'ff'ff) {
      if constexpr (InitReadAction == UpdateBufferSize)
        set_wrapped_buffer_size(peeked + 4);
      offset_size = 4;
      return read_value<u32>();
    } else {
      head += 4;
      const auto sz = read_value<u64>();
      if constexpr (InitReadAction == UpdateBufferSize)
        set_wrapped_buffer_size(sz + 12);
      offset_size = 8;
      return sz;
    }
  }

  /** Reads value from buffer according to dwarf spec, which can determine size of addresess, offsets etc. We
   * always make the results u64, but DWARF might represent the data as 32-bit values etc.*/
  u64 dwarf_spec_read_value() noexcept;
  template <IsBitsType T>
  constexpr auto
  read_uleb128() noexcept
  {
    T value;
    head = decode_uleb128(head, value);
    return value;
  }

  template <IsBitsType T>
  T
  read_leb128() noexcept
  {
    T value;
    head = decode_leb128(head, value);
    return value;
  }

  std::string_view read_string() noexcept;
  DataBlock read_block(u64 size) noexcept;
  const u8 *current_ptr() const noexcept;
  bool has_more() noexcept;
  u64 remaining_size() const noexcept;

  friend DwarfBinaryReader sub_reader(const DwarfBinaryReader &reader) noexcept;

private:
  void set_wrapped_buffer_size(u64 size) noexcept;
  const u8 *buffer;
  const u8 *head;
  const u8 *end;
  u64 size;
  u8 offset_size = 4;
};

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

template <typename T>
T *
mmap_file(ScopedFd &fd, u64 size, bool read_only) noexcept
{
  ASSERT(fd.is_open(), "Backing file not open: {}", fd.path().c_str());
  auto ptr = (T *)mmap(nullptr, size, read_only ? PROT_READ : PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0);
  ASSERT(ptr != MAP_FAILED, "Failed to mmap buffer of size {} from file {}", size, fd.path().c_str());
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

constexpr Option<TPtr<void>>
to_addr(std::string_view s)
{
  if (s.starts_with("0x"))
    s.remove_prefix(2);

  if (u64 value; std::from_chars(s.data(), s.data() + s.size(), value, 16).ec == std::errc{})
    return TPtr<void>{value};
  else
    return std::nullopt;
}

using SpinGuard = LockGuard<SpinLock>;

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