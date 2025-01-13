/** LICENSE TEMPLATE */
#pragma once
#include <typedefs.h>
#include <string_view>

namespace gdb {

enum class ArchId
{
  X86_64
};

// Defaulted to x86_64
struct RegisterNumbers
{
  u32 rip_number{16};
};

struct ArchInfo
{
  ArchId id{ArchId::X86_64};
  RegisterNumbers regs{};
};

std::pair<Pid, Tid> parse_thread_id(std::string_view arg) noexcept;

char *format_value(char *ptr, u32 value) noexcept;

u32 decode_rle(std::string_view v, char *buf, u32 size) noexcept;
std::string_view decode_rle_to_str(std::string_view v, char *buf, u32 size) noexcept;
} // namespace gdb
