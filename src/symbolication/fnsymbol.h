#pragma once
#include "../common.h"
#include "addr_sorter.h"
#include "dwarf/die.h"

namespace sym {

struct FunctionSymbol
{
  AddrPtr pc_start = nullptr;
  AddrPtr pc_end_exclusive = nullptr;
  std::string_view member_of{};
  std::string_view name{};
  std::array<dw::IndexedDieReference, 3> maybe_origin_dies;

  std::string build_full_name() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;

  static constexpr auto
  Sorter() noexcept
  {
    return AddressableSorter<FunctionSymbol, false>{};
  }
};
} // namespace sym