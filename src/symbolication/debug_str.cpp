#include "debug_str.h"

namespace sym {

DebugStringSection::DebugStringSection(const u8 *data) noexcept
{
  auto bit_room = __builtin_clzll(PtrVal(data));
  bit_mask = ~((1ULL << (64 - bit_room)) - 1);
}

const char *
DebugString::c_str(const DebugStringSection &sec) const noexcept
{
  return reinterpret_cast<const char *>((~(sec.bit_mask) & ptr));
}

std::string_view
DebugString::str_view(const DebugStringSection &sec) const noexcept
{
  auto str_size = sec.bit_mask & ptr;
  auto cstr_ptr = c_str(sec);
  return std::string_view{cstr_ptr, str_size};
}

} // namespace sym