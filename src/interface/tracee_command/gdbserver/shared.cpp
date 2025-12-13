/** LICENSE TEMPLATE */

// mdb
#include "shared.h"
#include <common.h>
#include <common/panic.h>

namespace mdb::gdb {

std::pair<SessionId, Tid>
ParseThreadId(std::string_view arg) noexcept
{
  MDB_ASSERT(arg[0] == 'p', "expected the multiprocess thread-id syntax.");
  arg.remove_prefix(1);
  const auto sep = arg.find('.');
  MDB_ASSERT(sep != arg.npos, "Expected thread-id syntax p<pid>.<tid>");
  SessionId pid{ 0 };
  Tid tid{ 0 };
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
FormatValue(char *ptr, u32 value) noexcept
{
  auto convert = std::to_chars(ptr, ptr + 8, value, 16);
  if (convert.ec != std::errc()) {
    return nullptr;
  }
  return convert.ptr;
}

u32
DecodeRunLengthEncoding(std::string_view v, char *buf, u32 size) noexcept
{
  auto ptr = buf;
  constexpr auto decodedSize = [](auto bptr, auto wptr) noexcept { return static_cast<u32>(wptr - bptr); };
  for (auto i = 0u; i < v.size() && decodedSize(buf, ptr) < size; ++i) {
    if (v[i] == '*') {
      const auto repeat_char = v[i - 1];
      const auto count = std::min(static_cast<u32>(v[i + 1] - 29), static_cast<u32>(size - (ptr - buf)));
      ptr = std::fill_n(ptr, count, repeat_char);
      ++i;
    } else {
      const auto c = v[i];
      // Branchless programming FTW: if it is not 'x', 1 * c + 0 = c, if it IS 'x': 0 * c + '0' * 1 = '0'
      const char res = (c != 'x') * c + ((c == 'x') * '0');
      *ptr = res;
      ++ptr;
    }
  }
  const auto sz = static_cast<u32>(ptr - buf);
  MDB_ASSERT(sz <= size, "buffer overflow assertion failed: {} <= {}", sz, size);
  return sz;
}

std::string_view
DecodeRunLengthEncToStringView(std::string_view v, char *buf, u32 size) noexcept
{
  const auto length = DecodeRunLengthEncoding(v, buf, size);
  return std::string_view{ buf, buf + length };
}

} // namespace mdb::gdb
