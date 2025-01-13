/** LICENSE TEMPLATE */
#include "block.h"

bool
AddressRange::Contains(AddressRange &block) const noexcept
{
  return block.low >= low && block.high <= high;
}

bool
AddressRange::Contains(AddrPtr ptr) const noexcept
{
  return ptr >= low && ptr < high;
}

bool
AddressRange::IsValid() const noexcept
{
  return low != TPtr<void>{nullptr} && high != TPtr<void>{nullptr};
}

AddrPtr
AddressRange::StartPc() const noexcept
{
  return low;
}

AddrPtr
AddressRange::EndPc() const noexcept
{
  return high;
}

AddressRange
AddressRange::relocate(AddressRange range, AddrPtr addr) noexcept
{
  return AddressRange{range.low + addr, range.high + addr};
}

void
BoundaryBuilder::CompareSwapLow(AddrPtr pc) noexcept
{
  low = std::min(low, pc);
}
void
BoundaryBuilder::CompareSwapHigh(AddrPtr pc) noexcept
{
  high = std::max(high, pc);
}

void
BoundaryBuilder::CompareBoundary(AddrPtr low, AddrPtr high) noexcept
{
  CompareSwapLow(low);
  CompareSwapHigh(high);
}

AddressRange
BoundaryBuilder::Build() const noexcept
{
  return AddressRange{low, high};
}