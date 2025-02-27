/** LICENSE TEMPLATE */
#include "base64.h"
#include <cmath>

namespace mdb {
consteval std::array<int, 256>
BaseTable() noexcept
{
  std::array<int, 256> result{};
  for (auto i = 0u; i < result.size(); ++i) {
    result[i] = -1;
  }

  for (auto i = 0; i < 64; ++i) {
    result["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
  }

  return result;
}

std::pmr::string
EncodeIntoBase64(std::span<std::uint8_t> data, std::pmr::memory_resource *resource) noexcept
{
  std::pmr::string buffer{resource};
  buffer.reserve(static_cast<size_t>((double)data.size() * 1.40));
  const auto chunks = std::floor((static_cast<float>(data.size()) / 3.0f));
  const auto total = chunks * 3;
  auto i = 0ul;
  for (; i < total; i += 3) {
    const std::uint16_t s0 = data[i];
    const std::uint16_t s1 = data[i + 1];
    const std::uint16_t s2 = data[i + 2];

    buffer.push_back(lookup_byte0[data[i]]);
    buffer.push_back(base64_lookup[(((s0 * 16) % 64) + (s1 / 16))]);
    buffer.push_back(base64_lookup[(((s1 * 4) % 64) + (s2 / 64))]);
    buffer.push_back(lookup_byte4[data[i + 2]]);
  }
  while (i < data.size()) {
    buffer.push_back('=');
    i++;
  }

  return buffer;
}

std::optional<std::pmr::vector<std::uint8_t>>
DecodeBase64(std::string_view encoded, std::pmr::memory_resource *resource) noexcept
{
  static constexpr auto Table = BaseTable();
  std::pmr::vector<std::uint8_t> out{resource};
  out.reserve(encoded.size() / 4 * 3 + 2);

  int val = 0, valb = -8;
  for (const auto c : encoded) {
    if (Table[c] == -1) {
      break;
    }
    val = (val << 6) + Table[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::optional<std::vector<std::uint8_t>>
decode_base64(std::string_view encoded) noexcept
{
  static constexpr auto Table = BaseTable();
  std::vector<std::uint8_t> out;
  out.reserve(encoded.size() / 4 * 3 + 2);

  int val = 0, valb = -8;
  for (const auto c : encoded) {
    if (Table[c] == -1) {
      break;
    }
    val = (val << 6) + Table[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::string
encode_base64(std::span<std::uint8_t> data) noexcept
{
  std::string buffer;
  buffer.reserve(static_cast<size_t>((double)data.size() * 1.40));
  const auto chunks = std::floor((static_cast<float>(data.size()) / 3.0f));
  const auto total = chunks * 3;
  auto i = 0ul;
  for (; i < total; i += 3) {
    const std::uint16_t s0 = data[i];
    const std::uint16_t s1 = data[i + 1];
    const std::uint16_t s2 = data[i + 2];

    buffer.push_back(lookup_byte0[data[i]]);
    buffer.push_back(base64_lookup[(((s0 * 16) % 64) + (s1 / 16))]);
    buffer.push_back(base64_lookup[(((s1 * 4) % 64) + (s2 / 64))]);
    buffer.push_back(lookup_byte4[data[i + 2]]);
  }
  while (i < data.size()) {
    buffer.push_back('=');
    i++;
  }

  return buffer;
}
} // namespace mdb