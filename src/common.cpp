/** LICENSE TEMPLATE */
// mdb
#include "common.h"
#include <common/panic.h>
#include <common/typedefs.h>

namespace mdb {
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
  panic(std::format("UNKNOWN SYSCALL NUMBER {}", syscall_number), std::source_location::current(), 1);
}

} // namespace mdb