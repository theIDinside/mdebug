#include "shared.h"

namespace gdb {

std::pair<Pid, Tid>
parse_thread_id(std::string_view arg) noexcept
{
  ASSERT(arg[0] == 'p', "expected the multiprocess thread-id syntax.");
  arg.remove_prefix(1);
  const auto sep = arg.find('.');
  ASSERT(sep != arg.npos, "Expected thread-id syntax p<pid>.<tid>");
  Pid pid{0};
  Tid tid{0};
  const auto res = std::from_chars(arg.data(), arg.data() + sep, pid, 16);
  if (res.ec != std::errc()) {
    PANIC("Failed to parse pid");
  }

  const auto res2 = std::from_chars(arg.data() + sep + 1, arg.data() + arg.size(), tid, 16);
  if (res2.ec != std::errc()) {
    PANIC("Failed to parse tid");
  }
  return std::make_pair(pid, tid);
}

char *
format_value(char *ptr, u32 value) noexcept
{
  auto convert = std::to_chars(ptr, ptr + 8, value, 16);
  if (convert.ec != std::errc()) {
    return nullptr;
  }
  return convert.ptr;
}
} // namespace gdb
