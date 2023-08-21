#pragma once
#include <common.h>

// SYMBOLS namespace
namespace sym {
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
};

class BoundsBuilder
{
private:
  u64 low = UINTMAX_MAX;
  u64 high = 0;

public:
  bool
  next(u64 l, u64 h) noexcept
  {
    if (l == 0 && h == 0)
      return false;
    low = std::min(l, low);
    high = std::max(h, high);
    return true;
  }

  AddressRange
  done(AddrPtr relocate_base) const noexcept
  {
    return AddressRange{relocate_base + low, relocate_base + high};
  }

  constexpr bool
  valid() const noexcept
  {
    return low != UINTMAX_MAX && high != 0;
  }
};
} // namespace sym