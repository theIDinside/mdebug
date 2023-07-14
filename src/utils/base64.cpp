#include "base64.h"

namespace utils {

std::string
encode_base64(std::span<std::uint8_t> data) noexcept
{
  std::string buffer;
  buffer.reserve(static_cast<size_t>((double)data.size() * 1.40));
  for (auto i = 0ul; i < data.size(); i += 3) {
    const std::uint16_t s0 = data[i];
    const std::uint16_t s1 = data[i + 1];
    const std::uint16_t s2 = data[i + 2];

    buffer.push_back(lookup_byte0[data[i]]);
    buffer.push_back(base64_lookup[(((s0 * 16) % 64) + (s1 / 16))]);
    buffer.push_back(base64_lookup[(((s1 * 4) % 64) + (s2 / 64))]);
    buffer.push_back(lookup_byte4[data[i + 2]]);
  }
  return buffer;
}
} // namespace utils