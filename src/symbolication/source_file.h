#pragma once
#include "../common.h"
#include "./dwarf/lnp.h"
#include "dwarf_defs.h"
#include "fnsymbol.h"
#include <iterator>
#include <optional>

using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;
namespace sym {

namespace dw {
class UnitData;
}

// A source file - represented by DW_TAG_compile_unit dies. The "largest" structural unit of a program that we
// define.
class CompilationUnit
{
  dw::UnitData *unit_data;
  AddrPtr low;
  AddrPtr high;
  dw::LineTable line_table;
  std::string_view cu_name;
  std::vector<sym::FunctionSymbol> fns;

public:
  struct SortByBounds
  {
    bool operator()(CompilationUnit &a, CompilationUnit &b);
  };

  CompilationUnit(dw::UnitData *cu_data) noexcept;

  CompilationUnit(const CompilationUnit &from) noexcept = delete;
  CompilationUnit &operator=(const CompilationUnit &from) noexcept = delete;

  CompilationUnit(CompilationUnit &&from) noexcept;
  CompilationUnit &operator=(CompilationUnit &&from) noexcept;

  void set_name(std::string_view name) noexcept;
  void set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept;
  void set_linetable(dw::LineTable line_table) noexcept;

  bool known_address() const noexcept;
  AddrPtr low_pc() const noexcept;
  AddrPtr high_pc() const noexcept;
  std::string_view name() const noexcept;
  bool function_symbols_resolved() const noexcept;
  std::optional<sym::FunctionSymbol> get_fn_by_pc(AddrPtr pc) noexcept;

private:
  void resolve_fn_symbols() noexcept;
  void maybe_create_fn_symbol(StringOpt name, StringOpt mangled_name, AddrOpt low_pc, AddrOpt high_pc) noexcept;
};
} // namespace sym