#include "block.h"

bool
AddressRange::contains(AddressRange &block) const noexcept
{
  return block.low.get() >= low.get() && block.high.get() <= high.get();
}

bool
AddressRange::contains(TPtr<void> ptr) const noexcept
{
  return ptr.get() >= low.get() && ptr.get() <= high.get();
}

bool
AddressRange::is_valid() const noexcept
{
  return low != TPtr<void>{nullptr} && high != TPtr<void>{nullptr};
}