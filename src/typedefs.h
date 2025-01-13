/** LICENSE TEMPLATE */
#pragma once

#include <cstdint>
#include <sys/types.h>
#include <type_traits>

using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u16 = std::uint16_t;
using u8 = std::uint8_t;

using i64 = std::int64_t;
using i32 = std::int32_t;
using i16 = std::int16_t;
using i8 = std::int8_t;

using Tid = pid_t;
using Pid = pid_t;

template <typename Fn, typename... FnArgs> using FnResult = std::invoke_result_t<Fn, FnArgs...>;