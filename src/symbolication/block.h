#pragma once
#include "addr_sorter.h"
#include <typedefs.h>

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

  static AddressRange relocate(AddressRange range, AddrPtr addr) noexcept;

  constexpr static auto
  Sorter()
  {
    return AddressableSorter<AddressRange, true>{};
  }

  friend bool
  operator==(const AddressRange &l, const AddressRange &r) noexcept
  {
    return l.low == r.low && l.high == r.high;
  }
};

class BoundaryBuilder
{
  AddrPtr high{nullptr};
  AddrPtr low{std::numeric_limits<u64>::max()};

public:
  void compare_swap_low(AddrPtr pc) noexcept;
  void compare_swap_high(AddrPtr pc) noexcept;
  void compare_boundary(AddrPtr low, AddrPtr high) noexcept;
  AddressRange build() const noexcept;
};