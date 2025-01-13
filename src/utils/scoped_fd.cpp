/** LICENSE TEMPLATE */
#include "scoped_fd.h"
#include "utils/scope_defer.h"
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

namespace utils {

ScopedFd::ScopedFd() noexcept : fd(-1), p{}, file_size_() {}

ScopedFd::ScopedFd(int fd, Path path) noexcept : fd(fd), p(std::move(path)), file_size_()
{
  if (fs::exists(p)) {
    struct stat s;
    if (-1 != stat(p.c_str(), &s)) {
      file_size_ = s.st_size;
    } else {
      file_size_ = 0;
    }
  } else {
    file_size_ = 0;
  }
  if (fd == -1) {
    DBGLOG(core, "[scopedfd]: Failed to open {}: {}", p.c_str(), strerror(errno));
  }
}

ScopedFd::ScopedFd(int fd) noexcept : fd(fd), file_size_()
{
  VERIFY(fd != -1, "Taking ownership of a closed file or error file: {}", strerror(errno));
}

ScopedFd::ScopedFd(ScopedFd &&other) noexcept : fd(other.fd) { other.fd = -1; }

ScopedFd &
ScopedFd::operator=(ScopedFd &&other) noexcept
{
  if (this == &other) {
    return *this;
  }
  close();
  fd = other.fd;
  p = std::move(other.p);
  file_size_ = other.file_size_;
  other.fd = -1;
  return *this;
}

ScopedFd::~ScopedFd() noexcept { close(); }

int
ScopedFd::get() const noexcept
{
  return fd;
}

bool
ScopedFd::is_open() const noexcept
{
  return fd != -1;
}

void
ScopedFd::close() noexcept
{
  if (fd >= 0) {
    const auto err = ::close(fd);
    if (err != 0 && err != -EINTR && err != EIO) {
      PANIC("Failed to close file");
    }
  }
  fd = -1;
}

ScopedFd::operator int() const noexcept { return get(); }

u64
ScopedFd::file_size() const noexcept
{
  if (file_size_) {
    return file_size_.value();
  }

  if (!is_open()) {
    return 0;
  }

  const auto curr = lseek(fd, 0, SEEK_CUR);
  ASSERT(-1 != curr, "Failed to fseek");
  auto size = lseek(fd, 0, SEEK_END);
  ASSERT((off_t)-1 != size, "Failed to get size");
  lseek(fd, curr, SEEK_SET);
  return size;
}

const Path &
ScopedFd::path() const noexcept
{
  return p;
}

void
ScopedFd::forget() noexcept
{
  p = "";
  fd = -1;
}

/* static */
ScopedFd
ScopedFd::open(const Path &p, int flags, mode_t mode) noexcept
{
  ASSERT(fs::exists(p), "File did not exist {}", p.c_str());
  return ScopedFd{::open(p.c_str(), flags, mode), p};
}

/* static */ utils::Expected<ScopedFd, ConnectError>
ScopedFd::socket_connect(const std::string &host, int port) noexcept
{
  addrinfo hints = {};
  addrinfo *result = nullptr;
  addrinfo *rp = nullptr;
  hints.ai_canonname = nullptr;
  hints.ai_addr = nullptr;
  hints.ai_next = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  auto port_number = std::to_string(port);
  if (getaddrinfo(host.c_str(), port_number.c_str(), &hints, &result) != 0) {
    DBGLOG(core, "getaddrinfo failed when attempting to connect to {}:{}. Reported reason: {}", host, port,
           strerror(errno));
    return ConnectError::AddrInfo(errno);
  }

  ScopedDefer defer{[&]() { freeaddrinfo(result); }};

  bool socket_error_only = true;
  for (rp = result; rp != nullptr; rp = rp->ai_next) {
    if (const auto fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); fd != -1) {
      if (::connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
        DBGLOG(core, "Successfully opened socket and connected to {}:{}", host, port);
        return ScopedFd{fd};
      } else {
        socket_error_only = false;
        ::close(fd);
      }
    }
  }
  if (socket_error_only) {
    DBGLOG(core, "Failed to connect to {}:{} due to socket error. Reported reason: {}", host, port,
           strerror(errno));
    return ConnectError::Socket(errno);
  }
  DBGLOG(core, "Failed to connect to {}:{}. Reported reason: {}", host, port, strerror(errno));
  return ConnectError::Connect(host, port, errno);
}

/* static */
ScopedFd
ScopedFd::open_read_only(const Path &p) noexcept
{
  return ScopedFd{::open(p.c_str(), O_RDONLY), p};
}

/*static*/
ScopedFd
ScopedFd::take_ownership(int fd) noexcept
{
  return ScopedFd{fd};
}
} // namespace utils