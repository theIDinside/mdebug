#pragma once
#include "../common.h"
#include "./dwarf/lnp.h"
#include "dwarf_defs.h"
#include <iterator>
#include <optional>

namespace sym {

namespace dw {
class UnitData;
}

// A source file - represented by DW_TAG_compile_unit dies. The "largest" structural unit of a program that we
// define.
class CompilationUnit
{
  dw::UnitData *unit_data;

  AddrPtr low_pc;
  AddrPtr high_pc;
  dw::LineTable line_table;

public:
  CompilationUnit(dw::UnitData *cu_data, dw::LineTable);
  void set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept;
  void set_linetable_header(dw::LNPHeader *header) noexcept;
};
} // namespace sym