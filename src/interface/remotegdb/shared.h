#pragma once
#include <common.h>
#include <tuple>
#include <typedefs.h>

namespace gdb {

std::pair<Pid, Tid> parse_thread_id(std::string_view arg) noexcept;

char *format_value(char *ptr, u32 value) noexcept;

} // namespace gdb
