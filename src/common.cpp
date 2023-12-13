#include "common.h"
#include "elf.h"
#include "fmt/core.h"
#include "utils/logger.h"
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <exception>
#include <execinfo.h>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <regex>
#include <source_location>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

Option<WaitPid>
waitpid_peek(pid_t tid) noexcept
{
  int status;
  const auto waited_pid = waitpid(tid, &status, __WALL | WNOHANG | WNOWAIT);
  if (waited_pid == 0)
    return {};
  if (waited_pid == -1)
    return {};

  return WaitPid{.tid = waited_pid, .status = status};
}

Option<WaitPid>
waitpid_nonblock(pid_t tid) noexcept
{
  int status;
  const auto waited_pid = waitpid(tid, &status, __WALL | WNOHANG);
  if (waited_pid == 0 || waited_pid == -1)
    return Option<WaitPid>{};
  return WaitPid{waited_pid, status};
}

Option<WaitPid>
waitpid_block(pid_t tid) noexcept
{
  int status;
  const auto waited_pid = waitpid(tid, &status, 0);
  if (waited_pid == 0 || waited_pid == -1)
    return Option<WaitPid>{};
  return WaitPid{waited_pid, status};
}

std::string_view
syscall_name(u64 syscall_number)
{
#define SYSCALL(num, name)                                                                                        \
  case num:                                                                                                       \
    return #name;
  switch (syscall_number) {
#include "defs/syscalls.def"
  }
#undef SYSCALL
  panic(fmt::format("UNKNOWN SYSCALL NUMBER {}", syscall_number), std::source_location::current(), 1);
}

template <typename T>
void
replace_regex(T &str)
{
  static const std::regex str_view_regex("std::basic_string_view<char, std::char_traits<char> >");
  static const std::regex str_regex{
      "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >"};
  static const std::regex allocator_regex{", std::allocator<.*> "};

  const std::string replacement = "std::string_view";
  str = std::regex_replace(str, str_view_regex, replacement);

  const std::string str_replacement = "std::string";
  str = std::regex_replace(str, str_regex, str_replacement);

  const std::string allocator_replacement = "";
  str = std::regex_replace(str, allocator_regex, allocator_replacement);
}

static void
sanitize(std::string &name)
{
  replace_regex(name);
}

[[noreturn]] static void
panic_exit()
{
  if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
    raise(SIGTERM);
    exit(-1);
  } else
    exit(-1);
}

void
panic(std::string_view err_msg, const std::source_location &loc, int strip_levels)
{
  constexpr auto BT_BUF_SIZE = 100;
  int nptrs;
  void *buffer[BT_BUF_SIZE];
  char **strings;

  nptrs = backtrace(buffer, BT_BUF_SIZE);
  logging::get_logging()->log("mdb", fmt::format("backtrace() returned {} addresses\n", nptrs));
  fmt::println("backtrace() returned {} addresses\n", nptrs);

  /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
     would produce similar output to the following: */

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    perror("backtrace_symbols");
    goto ifbacktrace_failed;
  }

  for (int j = strip_levels; j < nptrs; j++) {
    auto demangle_len = 0ul;
    int stat = 0;
    std::string_view view{strings[j]};
    if (const auto p = view.find_first_of("_Z"); p != std::string_view::npos) {
      view.remove_prefix(p);
      view.remove_suffix(view.size() - view.find_first_of("+"));
      std::string copy{view};
      if (const auto res = __cxxabiv1::__cxa_demangle(copy.data(), nullptr, &demangle_len, &stat); stat == 0) {
        std::string copy{res};
        sanitize(copy);
        logging::get_logging()->log("mdb", copy);
        fmt::println("{}", copy);
        continue;
      }
    }
    logging::get_logging()->log("mdb", strings[j]);
    fmt::println("{}", strings[j]);
  }

  free(strings);
ifbacktrace_failed:
  logging::get_logging()->log(
      "mdb", fmt::format("--- [PANIC] ---\n[FILE]: {}:{}\n[FUNCTION]: {}\n[REASON]: {}\n--- [PANIC] ---",
                         loc.file_name(), loc.line(), loc.function_name(), err_msg));

  fmt::println(
      "{}", fmt::format("--- [PANIC] ---\n[FILE]: {}:{}\n[FUNCTION]: {}\n[REASON]: {}\nErrno: {}--- [PANIC] ---",
                        loc.file_name(), loc.line(), loc.function_name(), err_msg, errno));
  delete logging::get_logging();
  panic_exit();
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
  ASSERT(fd != -1, "Failed to open {} [{}]", p.c_str(), strerror(errno));
}

ScopedFd::ScopedFd(int fd) noexcept : fd(fd)
{
  VERIFY(fd != -1, "Taking ownership of a closed file or error file: {}", strerror(errno));
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
      PANIC("Failed to close file");
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

Option<AddrPtr>
to_addr(std::string_view s) noexcept
{
  if (s.starts_with("0x"))
    s.remove_prefix(2);

  if (u64 value; std::from_chars(s.data(), s.data() + s.size(), value, 16).ec == std::errc{})
    return AddrPtr{value};
  else
    return std::nullopt;
}

u64
get_register(user_regs_struct *regs, int reg_number) noexcept
{
  ASSERT(reg_number <= 16, "Register number {} not supported", reg_number);
  return *(u64 *)(((std::uintptr_t)regs) + offsets[reg_number]);
}