/** LICENSE TEMPLATE */
#pragma once
#include <cstdint>
#include <string_view>
#include <typedefs.h>

using PtrVal = std::uintptr_t;

namespace sym {

class DebugString;

// The .debug_str section in the ELF binary
class DebugStringSection
{
  u64 bit_mask;
  PtrVal mapped_in_addr_start;
  PtrVal mapped_in_addr_end;
  friend class DebugString;

public:
  DebugStringSection(const u8 *data) noexcept;

  const char *decode(const DebugString &dbg_str) noexcept;
};

class DebugString
{
public:
  DebugString(const char *str);
  const char *c_str(const DebugStringSection &sec) const noexcept;
  std::string_view str_view(const DebugStringSection &sec) const noexcept;

private:
  PtrVal ptr;
};

}; // namespace sym