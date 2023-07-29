#pragma once
#include "../common.h"

/**
 * Description of a range of executable code, inside of a compilation unit.
 */
struct AddressRange
{
  AddrPtr low;
  AddrPtr high;
  bool contains(AddressRange &range) const noexcept;
  bool contains(AddrPtr ptr) const noexcept;
  bool is_valid() const noexcept;
};