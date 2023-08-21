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