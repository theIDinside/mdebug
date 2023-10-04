#pragma once

#include "symbol/dwarf2/unit.h"

namespace sym::dw2 {
class AttributeReader
{

private:
  // The actual data reader
  UnitReader reader;
};
} // namespace sym::dw2