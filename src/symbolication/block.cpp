#include "block.h"

bool
AddressRange::contains(AddressRange &block) const noexcept
{
  return block.low >= low && block.high <= high;
}

bool
AddressRange::contains(AddrPtr ptr) const noexcept
{
  return ptr >= low && ptr < high;
}

bool
AddressRange::is_valid() const noexcept
{
  return low != TPtr<void>{nullptr} && high != TPtr<void>{nullptr};
}

AddrPtr
AddressRange::start_pc() const noexcept
{
  return low;
}

AddrPtr
AddressRange::end_pc() const noexcept
{
  return high;
}

AddressRange
AddressRange::relocate(AddressRange range, AddrPtr addr) noexcept
{
  return AddressRange{range.low + addr, range.high + addr};
}

void
BoundaryBuilder::compare_swap_low(AddrPtr pc) noexcept
{
  low = std::min(low, pc);
}
void
BoundaryBuilder::compare_swap_high(AddrPtr pc) noexcept
{
  high = std::max(high, pc);
}

void
BoundaryBuilder::compare_boundary(AddrPtr low, AddrPtr high) noexcept
{
  compare_swap_low(low);
  compare_swap_high(high);
}

AddressRange
BoundaryBuilder::build() const noexcept
{
  return AddressRange{low, high};
}