#pragma once
#include <common.h>
#include <tuple>
#include <typedefs.h>

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

} // namespace gdb
