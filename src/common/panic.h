/** LICENSE TEMPLATE */

#include <string_view>

namespace std {
struct source_location;
} // namespace std

// defines PANIC macro. Responsibility on caller to include required headers.

#define PANIC(err_msg)                                                                                            \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    mdb::panic(err_msg, loc, 1);                                                                                  \
  }

#define NEVER(msg)                                                                                                \
  PANIC(msg);                                                                                                     \
  MIDAS_UNREACHABLE

#ifndef MIDAS_UNREACHABLE

#if defined(__clang__)
#define MIDAS_UNREACHABLE std::unreachable();
#elif defined(__GNUC__) || defined(__GNUG__)
#define MIDAS_UNREACHABLE __builtin_unreachable();
#endif

#endif

[[noreturn]] void panic(std::string_view err_msg, const char *functionName, const char *file, int line,
                        int strip_levels);

void panic(std::string_view err_msg, const std::source_location &loc, int strip_levels);
