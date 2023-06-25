#include "common.h"
#include "fmt/core.h"
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>

void
panic(std::string_view err_msg)
{
  constexpr auto BT_BUF_SIZE = 100;
  int nptrs;
  void *buffer[BT_BUF_SIZE];
  char **strings;

  nptrs = backtrace(buffer, BT_BUF_SIZE);
  fmt::println("backtrace() returned {} addresses\n", nptrs);

  /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
     would produce similar output to the following: */

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (int j = 0; j < nptrs; j++)
    fmt::println("{}", strings[j]);

  free(strings);

  fmt::print("[PANIC]: {}\n", err_msg);
  exit(EXIT_FAILURE);
}

ScopedFd::ScopedFd(int fd, Path path) noexcept : fd(fd), p(std::move(path))
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
  fmt::println("File size: {}", file_size_);
  if (fd == -1)
    panic(fmt::format("Failed to open {} [{}]", p.c_str(), strerror(errno)));
}

ScopedFd::~ScopedFd() noexcept { close(); }

ScopedFd::ScopedFd(ScopedFd &&other) noexcept : fd(other.fd) { other.fd = -1; }

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
      panic("Failed to open file");
    }
  }
  fd = -1;
}

ScopedFd::operator int() const noexcept { return get(); }

u64
ScopedFd::file_size() const noexcept
{
  if (file_size_ > 0)
    return file_size_;

  if (!is_open()) {
    return 0;
  }

  const auto curr = lseek(fd, 0, SEEK_CUR);
  if ((off_t)-1 == curr)
    panic("Failed to lseek");
  auto size = lseek(fd, 0, SEEK_END);
  if ((off_t)-1 == size)
    panic("Failed to lseek");
  if ((off_t)-1 == lseek(fd, curr, SEEK_SET))
    panic("Failed to lseek");
  return size;
}

/* static */
ScopedFd
ScopedFd::open(const Path &p, int flags, mode_t mode) noexcept
{
  if (!fs::exists(p)) {
    panic(fmt::format("File did not exist {}", p.c_str()));
  }

  return ScopedFd{::open(p.c_str(), flags, mode), p};
}

/* static */
ScopedFd
ScopedFd::open_read_only(const Path &p) noexcept
{
  return ScopedFd{::open(p.c_str(), O_RDONLY), p};
}