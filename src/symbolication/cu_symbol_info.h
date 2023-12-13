#pragma once
#include "../common.h"
#include "./dwarf/lnp.h"
#include "block.h"
#include "dwarf/common.h"
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

class PartialCompilationUnitSymbolInfo
{
  dw::UnitData *unit_data;
  dw::LineTable line_table;
  std::vector<sym::FunctionSymbol> fns;
  std::vector<u32> imported_units;

public:
  PartialCompilationUnitSymbolInfo(dw::UnitData *data) noexcept;
  PartialCompilationUnitSymbolInfo(PartialCompilationUnitSymbolInfo &&) noexcept;
  PartialCompilationUnitSymbolInfo &operator=(PartialCompilationUnitSymbolInfo &&) noexcept;
  // Deleted
  PartialCompilationUnitSymbolInfo(const PartialCompilationUnitSymbolInfo &) noexcept = delete;
  PartialCompilationUnitSymbolInfo &operator=(const PartialCompilationUnitSymbolInfo &) noexcept = delete;
};

class CompilationUnitSymbolInfo
{
  dw::UnitData *unit_data;
  AddrPtr pc_start;
  AddrPtr pc_end_exclusive;
  dw::LineTable line_table;
  std::string_view cu_name;
  std::vector<sym::FunctionSymbol> fns;
  std::vector<u32> imported_units;
  SymbolInfoId id;

public:
  CompilationUnitSymbolInfo(dw::UnitData *cu_data) noexcept;

  CompilationUnitSymbolInfo(const CompilationUnitSymbolInfo &from) noexcept = delete;
  CompilationUnitSymbolInfo &operator=(const CompilationUnitSymbolInfo &from) noexcept = delete;

  CompilationUnitSymbolInfo(CompilationUnitSymbolInfo &&from) noexcept;
  CompilationUnitSymbolInfo &operator=(CompilationUnitSymbolInfo &&from) noexcept;

  void set_name(std::string_view name) noexcept;
  void set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept;
  void set_linetable(dw::LineTable line_table) noexcept;
  void set_id(SymbolInfoId id) noexcept;

  bool known_address_boundary() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;
  std::string_view name() const noexcept;
  bool function_symbols_resolved() const noexcept;
  std::optional<sym::FunctionSymbol> get_fn_by_pc(AddrPtr pc) noexcept;
  dw::UnitData *get_dwarf_unit() const noexcept;

  static constexpr auto
  Sorter() noexcept
  {
    return AddressableSorter<CompilationUnitSymbolInfo, false>{};
  }

private:
  void resolve_fn_symbols() noexcept;
  void maybe_create_fn_symbol(StringOpt name, StringOpt mangled_name, AddrOpt low_pc, AddrOpt high_pc) noexcept;
};
} // namespace sym