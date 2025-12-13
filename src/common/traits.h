/** LICENSE TEMPLATE */
#pragma once

#include <type_traits>

template <typename T, typename U> inline constexpr bool IsType = std::is_same_v<T, U>;