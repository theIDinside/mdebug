#pragma once
#include "../common.h"
#include "addr_sorter.h"

/**
 * Description of a range of executable code, inside of a compilation unit.
 */
struct AddressRange
{
  AddrPtr low;
  AddrPtr high;

  // useful when we want to iteratively find low and high
  static constexpr AddressRange
  MaxMin() noexcept
  {
    return AddressRange{AddrPtr::Max(), AddrPtr::Min()};
  }
  bool contains(AddressRange &range) const noexcept;
  bool contains(AddrPtr ptr) const noexcept;
  bool is_valid() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;

  constexpr static auto
  Sorter()
  {
    return AddressableSorter<AddressRange, true>{};
  }
};