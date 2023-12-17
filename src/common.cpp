#include "common.h"
#include "fmt/core.h"
#include "utils/logger.h"
#include <cxxabi.h>
#include <execinfo.h>
#include <fcntl.h>
#include <optional>
#include <regex>
#include <source_location>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>

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