#include "scoped_fd.h"
#include <fcntl.h>
#include <sys/stat.h>

namespace utils {

ScopedFd::ScopedFd() noexcept : fd(-1), p{}, file_size_() {}

ScopedFd::ScopedFd(int fd, Path path) noexcept : fd(fd), p(std::move(path)), file_size_()
{
  if (fs::exists(p)) {
    struct stat s;
    if (-1 != stat(p.c_str(), &s))
      file_size_ = s.st_size;
    else
      file_size_ = 0;
  } else {
    file_size_ = 0;
  }
  ASSERT(fd != -1, "Failed to open {} [{}]", p.c_str(), strerror(errno));
}

ScopedFd::ScopedFd(int fd) noexcept : fd(fd), file_size_()
{
  VERIFY(fd != -1, "Taking ownership of a closed file or error file: {}", strerror(errno));
}

ScopedFd::ScopedFd(ScopedFd &&other) noexcept : fd(other.fd) { other.fd = -1; }

ScopedFd &
ScopedFd::operator=(ScopedFd &&other) noexcept
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
  if (file_size_)
    return file_size_.value();

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