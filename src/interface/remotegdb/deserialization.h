#pragma once

#include "typedefs.h"
#include <algorithm>
#include <common.h>
#include <string_view>

namespace mdb {

u8 fromhex(char a) noexcept;

template <typename Container>
constexpr void
deserialize_hex_encoded(std::string_view hex, Container &out) noexcept
{
  auto p = out.Data();

  constexpr auto repeat = [](char c) noexcept -> u32 { return static_cast<u32>(c - char{29}); };
  while (!hex.empty()) {
    // at what position `i` is the to-be-repeated-character
    auto i = hex[0] == '*' ? -1 : (hex[1] == '*' ? 0 : 1);
    if (i < 1) {
      // repeat count => the encoded repeat value, which is value of (char at hex of i + 2) - 29
      const auto r = repeat(hex[i + 2]);
      const auto repeat_uneven = (r & 0b1) == 1;
      const auto hex0_is_rep = (i == -1);
      const auto add_sz = (repeat_uneven) ? 1 : (hex0_is_rep ? 0 : 2);
      const auto buf_sz = r + add_sz;
      char buf[buf_sz]; // NOLINT
      std::fill_n(buf, buf_sz, *(hex.data() + i));
      const auto add_after_0 = hex0_is_rep && repeat_uneven;
      const auto add_after_1 = !hex0_is_rep && !repeat_uneven;
      buf[buf_sz - 1] = add_after_0 ? *(hex.data() + 2) : (add_after_1 ? *(hex.data() + 3) : buf[buf_sz - 1]);
      // this is safe, because we've made sure buf_sz % 2 == 0. I think.
      std::string_view view{buf, buf_sz};
      while (!view.empty()) {
        *p = (fromhex(view[0]) << 4) | (fromhex(view[1]));
        view.remove_prefix(2);
        ++p;
      }
      const auto remove_count_hex_0 = add_after_0 ? 3 : 2;
      const auto remove_count_hex_1 = add_after_1 ? 4 : 3;
      const auto remove_count = hex0_is_rep ? remove_count_hex_0 : remove_count_hex_1;
      hex.remove_prefix(remove_count);
    } else {
      *p = (fromhex(hex[0]) << 4) | (fromhex(hex[1]));
      hex.remove_prefix(2);
      ++p;
    }
  }
  ASSERT(p <= (out.Data(out.Size())), "Stack buffer overrun. Array of {} bytes overrun by {} bytes", out.Size(),
         static_cast<u64>(p - (out.Data(out.Size()))));
}

template <size_t N>
constexpr void
deserialize_hex_encoded(std::string_view hex, std::array<u8, N> &out) noexcept
{
  auto p = out.data();

  constexpr auto repeat = [](char c) noexcept -> u32 { return static_cast<u32>(c - char{29}); };

  while (!hex.empty()) {
    // at what position `i` is the to-be-repeated-character
    auto i = hex[0] == '*' ? -1 : (hex[1] == '*' ? 0 : 1);
    if (i < 1) {
      // repeat count => the encoded repeat value, which is value of (char at hex of i + 2) - 29
      const auto r = repeat(hex[i + 2]);
      const auto repeat_uneven = (r & 0b1) == 1;
      const auto hex0_is_rep = (i == -1);
      const auto add_sz = (repeat_uneven) ? 1 : (hex0_is_rep ? 0 : 2);
      const auto buf_sz = r + add_sz;
      char buf[buf_sz]; // NOLINT
      std::fill_n(buf, buf_sz, *(hex.data() + i));
      const auto add_after_0 = hex0_is_rep && repeat_uneven;
      const auto add_after_1 = !hex0_is_rep && !repeat_uneven;
      buf[buf_sz - 1] = add_after_0 ? *(hex.data() + 2) : (add_after_1 ? *(hex.data() + 3) : buf[buf_sz - 1]);
      // this is safe, because we've made sure buf_sz % 2 == 0. I think.
      std::string_view view{buf, buf_sz};
      while (!view.empty()) {
        *p = (fromhex(view[0]) << 4) | (fromhex(view[1]));
        view.remove_prefix(2);
        ++p;
      }
      const auto remove_count_hex_0 = add_after_0 ? 3 : 2;
      const auto remove_count_hex_1 = add_after_1 ? 4 : 3;
      const auto remove_count = hex0_is_rep ? remove_count_hex_0 : remove_count_hex_1;
      hex.remove_prefix(remove_count);
    } else {
      *p = (fromhex(hex[0]) << 4) | (fromhex(hex[1]));
      hex.remove_prefix(2);
      ++p;
    }
  }
  ASSERT(p < (out.data() + out.size()), "Stack buffer overrun. Array of {} bytes overrun by {} bytes", out.size(),
         static_cast<u64>(p - (out.data() + out.size())));
}
} // namespace mdb