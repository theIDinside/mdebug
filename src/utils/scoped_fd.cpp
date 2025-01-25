/** LICENSE TEMPLATE */
#include "scoped_fd.h"
#include "utils/logger.h"
#include "utils/scope_defer.h"
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

namespace utils {

ScopedFd::ScopedFd() noexcept : mFd(-1), mPath{}, mFileSize() {}

ScopedFd::ScopedFd(int fd, Path path) noexcept : mFd(fd), mPath(std::move(path)), mFileSize()
{
  if (fs::exists(mPath)) {
    struct stat s;
    if (-1 != stat(mPath.c_str(), &s)) {
      mFileSize = s.st_size;
    } else {
      mFileSize = 0;
    }
  } else {
    mFileSize = 0;
  }
  if (fd == -1) {
    DBGLOG(core, "[scopedfd]: Failed to open {}: {}", mPath.c_str(), strerror(errno));
  }
}

ScopedFd::ScopedFd(int fd) noexcept : mFd(fd), mFileSize()
{
  VERIFY(fd != -1, "Taking ownership of a closed file or error file: {}", strerror(errno));
}

ScopedFd::ScopedFd(ScopedFd &&other) noexcept : mFd(other.mFd) { other.mFd = -1; }

ScopedFd &
ScopedFd::operator=(ScopedFd &&other) noexcept
{
  if (this == &other) {
    return *this;
  }
  Close();
  mFd = other.mFd;
  mPath = std::move(other.mPath);
  mFileSize = other.mFileSize;
  other.mFd = -1;
  return *this;
}

ScopedFd::~ScopedFd() noexcept { Close(); }

int
ScopedFd::Get() const noexcept
{
  return mFd;
}

bool
ScopedFd::IsOpen() const noexcept
{
  return mFd != -1;
}

void
ScopedFd::Close() noexcept
{
  if (mFd >= 0) {
    const auto err = ::close(mFd);
    if (err != 0 && err != -EINTR && err != EIO) {
      PANIC("Failed to close file");
    }
  }
  mFd = -1;
}

ScopedFd::operator int() const noexcept { return Get(); }

u64
ScopedFd::FileSize() const noexcept
{
  if (mFileSize) {
    return mFileSize.value();
  }

  if (!IsOpen()) {
    return 0;
  }

  const auto curr = lseek(mFd, 0, SEEK_CUR);
  ASSERT(-1 != curr, "Failed to fseek");
  auto size = lseek(mFd, 0, SEEK_END);
  ASSERT((off_t)-1 != size, "Failed to get size");
  lseek(mFd, curr, SEEK_SET);
  return size;
}

const Path &
ScopedFd::GetPath() const noexcept
{
  return mPath;
}

void
ScopedFd::Release() noexcept
{
  mPath = "";
  mFd = -1;
}

/* static */
ScopedFd
ScopedFd::Open(const Path &p, int flags, mode_t mode) noexcept
{
  ASSERT(fs::exists(p), "File did not exist {}", p.c_str());
  return ScopedFd{::open(p.c_str(), flags, mode), p};
}

/* static */ utils::Expected<ScopedFd, ConnectError>
ScopedFd::OpenSocketConnectTo(const std::string &host, int port) noexcept
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
ScopedFd::OpenFileReadOnly(const Path &p) noexcept
{
  return ScopedFd{::open(p.c_str(), O_RDONLY), p};
}

/*static*/
ScopedFd
ScopedFd::TakeFileDescriptorOwnership(int fd) noexcept
{
  return ScopedFd{fd};
}
} // namespace utils