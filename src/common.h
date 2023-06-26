#pragma once

#include <cstddef>
#include <cstdint>
#include <execinfo.h>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <source_location>
#include <span>
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

void panic(std::string_view err_msg, const std::source_location &loc_msg, int strip_levels = 0);

#define PANIC(err_msg)                                                                                            \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    panic(err_msg, loc, 1);                                                                                       \
  }

template <typename FormatString, typename... Args>
void
assert(bool is_true, FormatString fmt, Args... args)
{
  if (!is_true) {
    panic(fmt::format(fmt, args...));
  }
}

#ifdef MDB_DEBUG
#define ASSERT(cond, msg, ...)                                                                                    \
  {                                                                                                               \
    std::source_location loc = std::source_location::current();                                                   \
    if (!(cond)) {                                                                                                \
      panic(fmt::format("{} FAILED {}", #cond, fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)), loc);                \
    }                                                                                                             \
  }
#else
#define ASSERT(cond, msg, ...)
#endif

template <typename T>
constexpr bool
is_nullptr_t(T)
{
  return std::is_same_v<T, std::nullptr_t>;
}

template <typename T> class TraceePointer
{
public:
  TraceePointer() : remote_addr{0} {}
  TraceePointer(uintptr_t address) noexcept : remote_addr(address) {}
  uintptr_t
  get() const noexcept
  {
    return remote_addr;
  }

  /**
   * Cast this TraceePointer<T> to TraceePointer<U>
   */
  template <typename U>
  TraceePointer<U>
  as() const
  {
    return TraceePointer<U>{get()};
  }

private:
  std::uintptr_t remote_addr;
};

class ScopedFd
{
public:
  ScopedFd() noexcept : fd(-1), p{} {}
  ScopedFd(int fd, Path p) noexcept;
  ~ScopedFd() noexcept;

  ScopedFd &
  operator=(ScopedFd &&other) noexcept
  {
    if (this == &other)
      return *this;
    fd = other.fd;
    p = std::move(other.p);
    file_size_ = other.file_size_;
    other.fd = -1;
    other.p = "";
    return *this;
  }

  ScopedFd(ScopedFd &&) noexcept;

  int get() const noexcept;
  bool is_open() const noexcept;
  void close() noexcept;
  operator int() const noexcept;
  u64 file_size() const noexcept;

  static ScopedFd open(const Path &p, int flags, mode_t mode = mode_t{0}) noexcept;
  static ScopedFd open_read_only(const Path &p) noexcept;

private:
  int fd;
  Path p;
  u64 file_size_;
};