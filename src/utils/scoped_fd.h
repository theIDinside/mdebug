/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "utils/expected.h"
#include <filesystem>
#include <sys/mman.h>
#include <typedefs.h>

using Path = std::filesystem::path;

struct ConnectError
{

  enum class Kind
  {
    GetAddressInfo,
    Socket,
    Connect
  };

  Kind kind;
  std::string msg;
  int sys_errno;

  static ConnectError
  AddrInfo(int sys)
  {
    return ConnectError{.kind = Kind::GetAddressInfo, .msg = "getaddrinfo failed", .sys_errno = sys};
  }

  static ConnectError
  Socket(int sys) noexcept
  {
    return ConnectError{.kind = Kind::Socket, .msg = "Failed to open socket", .sys_errno = sys};
  }

  static ConnectError
  Connect(const std::string &host, int port, int sys) noexcept
  {
    return ConnectError{
      .kind = Kind::Connect, .msg = fmt::format("Failed to connect to {}:{}", host, port), .sys_errno = sys};
  }
};

namespace utils {
class ScopedFd
{
public:
  ScopedFd() noexcept;
  ScopedFd(int fd) noexcept;
  ScopedFd(int fd, Path p) noexcept;
  ScopedFd &operator=(ScopedFd &&other) noexcept;
  ScopedFd(ScopedFd &&) noexcept;
  ~ScopedFd() noexcept;

  int get() const noexcept;
  bool is_open() const noexcept;
  void close() noexcept;
  operator int() const noexcept;
  u64 file_size() const noexcept;
  const Path &path() const noexcept;
  void forget() noexcept;

  template <typename T>
  T *
  mmap_file(std::optional<u64> opt_size, bool read_only) noexcept
  {
    ASSERT(is_open(), "Backing file not open: {}", path().c_str());
    const auto size = opt_size.value_or(file_size());
    auto ptr = (T *)mmap(nullptr, size, read_only ? PROT_READ : PROT_READ | PROT_WRITE, MAP_PRIVATE, get(), 0);
    ASSERT(ptr != MAP_FAILED, "Failed to mmap buffer of size {} from file {}", size, path().c_str());
    return ptr;
  }

  static ScopedFd open(const Path &p, int flags, mode_t mode = mode_t{0}) noexcept;
  static utils::Expected<ScopedFd, ConnectError> socket_connect(const std::string &host, int port) noexcept;
  static ScopedFd open_read_only(const Path &p) noexcept;
  static ScopedFd take_ownership(int fd) noexcept;

private:
  int fd;
  Path p;
  std::optional<u64> file_size_;
};
} // namespace utils