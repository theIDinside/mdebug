#pragma once
#include <cstdint>

using u32 = std::uint32_t;
using u64 = std::uint64_t;

namespace sym {
struct SymbolInfoId
{
  u32 id;

  constexpr operator u32() const noexcept { return id; }
  constexpr operator u64() const noexcept { return id; }
};
}; // namespace sym