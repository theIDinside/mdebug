#include "panic.h"

// mdb
#include <utils/logger.h>

// stdlib
#include <print>
#include <regex>

// system
#include <csignal>
#include <cxxabi.h>
#include <execinfo.h>
#include <sys/ptrace.h>
#include <sys/user.h>

namespace mdb {
template <typename T>
void
replace_regex(T &str)
{
  static const std::regex str_view_regex("std::basic_string_view<char, std::char_traits<char> >");
  static const std::regex str_regex{
    "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >"
  };
  static const std::regex allocator_regex{ ", std::allocator<.*> " };

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
    raise(SIGTRAP);
    exit(-1);
  } else {
    raise(SIGTRAP);
    exit(-1);
  }
}

[[noreturn]] void
panic(std::string_view err_msg, const char *functionName, const char *file, int line, int strip_levels)
{
  using enum Channel;
  constexpr auto logIf = [](std::string_view msg) { logging::Logger::LogIf(core, msg); };
  constexpr auto BT_BUF_SIZE = 100;
  int nptrs;
  void *buffer[BT_BUF_SIZE];
  char **strings;
  nptrs = backtrace(buffer, BT_BUF_SIZE);
  logIf(std::format("backtrace() returned {} addresses\n", nptrs));
  std::println("backtrace() returned {} addresses\n", nptrs);

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
    std::string_view view{ strings[j] };
    if (const auto p = view.find_first_of("_Z"); p != std::string_view::npos) {
      view.remove_prefix(p);
      view.remove_suffix(view.size() - view.find_first_of('+'));
      std::string copy{ view };
      if (const auto res = __cxxabiv1::__cxa_demangle(copy.data(), nullptr, &demangle_len, &stat); stat == 0) {
        std::string copy{ res };
        sanitize(copy);
        logIf(copy);
        std::println("{}", copy);
        continue;
      }
    }
    logIf(strings[j]);
    std::println("{}", strings[j]);
  }

  free(strings);
ifbacktrace_failed:
  const auto strerr = strerror(errno);
  const auto message =
    std::format("--- [PANIC] ---\n[FILE]: {}:{}\n[FUNCTION]: {}\n[REASON]: {}\nErrno: {}: {}\n--- [PANIC] ---",
      file,
      line,
      functionName,
      err_msg,
      errno,
      strerr);
  logIf(message);
  std::println("{}", message);
  delete logging::Logger::GetLogger();
  panic_exit();
}

void
panic(std::string_view err_msg, const std::source_location &loc, int strip_levels)
{
  panic(err_msg, loc.function_name(), loc.file_name(), loc.line(), strip_levels);
}
} // namespace mdb