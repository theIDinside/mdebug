/** LICENSE TEMPLATE */
#pragma once
#include <common/typedefs.h>

namespace mdb::sym {
struct SymbolInfoId
{
  u32 id;

  constexpr
  operator u32() const noexcept
  {
    return id;
  }
  constexpr
  operator u64() const noexcept
  {
    return id;
  }
};
}; // namespace mdb::sym