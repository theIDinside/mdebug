#pragma once
#include "../common.h"

/**
 * Description of a range of executable code, inside of a compilation unit.
 */
struct AddressRange
{
  TPtr<void> low;
  TPtr<void> high;
  bool contains(AddressRange &range) const noexcept;
  bool contains(TPtr<void> ptr) const noexcept;
  bool is_valid() const noexcept;
};