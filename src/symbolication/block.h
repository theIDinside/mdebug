/** LICENSE TEMPLATE */
#pragma once
#include "addr_sorter.h"
#include <typedefs.h>

namespace mdb {
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
  bool Contains(AddressRange &range) const noexcept;
  bool Contains(AddrPtr ptr) const noexcept;
  bool IsValid() const noexcept;
  AddrPtr StartPc() const noexcept;
  AddrPtr EndPc() const noexcept;

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
  void CompareSwapLow(AddrPtr pc) noexcept;
  void CompareSwapHigh(AddrPtr pc) noexcept;
  void CompareBoundary(AddrPtr low, AddrPtr high) noexcept;
  AddressRange Build() const noexcept;
};
} // namespace mdb