/** LICENSE TEMPLATE */
#pragma once
#include <string_view>
#include <typedefs.h>

namespace mdb::gdb {

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

std::pair<Pid, Tid> ParseThreadId(std::string_view arg) noexcept;

char *FormatValue(char *ptr, u32 value) noexcept;

u32 DecodeRunLengthEncoding(std::string_view v, char *buf, u32 size) noexcept;
std::string_view DecodeRunLengthEncToStringView(std::string_view v, char *buf, u32 size) noexcept;
} // namespace mdb::gdb
