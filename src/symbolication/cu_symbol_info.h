#pragma once
#include "./dwarf/lnp.h"
#include "block.h"
#include "dwarf/common.h"
#include "dwarf_defs.h"
#include "fnsymbol.h"
#include "utils/interval_map.h"
#include <common.h>
#include <iterator>
#include <optional>

using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;
struct ObjectFile;
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

class SourceFileSymbolInfo
{
  dw::UnitData *unit_data;
  AddrPtr pc_start;
  AddrPtr pc_end_exclusive;
  u64 line_table;
  std::string_view cu_name;
  std::vector<sym::FunctionSymbol> fns;
  std::vector<u32> imported_units;
  SymbolInfoId id;

public:
  SourceFileSymbolInfo(dw::UnitData *cu_data) noexcept;

  SourceFileSymbolInfo(const SourceFileSymbolInfo &from) noexcept = delete;
  SourceFileSymbolInfo &operator=(const SourceFileSymbolInfo &from) noexcept = delete;

  SourceFileSymbolInfo(SourceFileSymbolInfo &&from) noexcept;
  SourceFileSymbolInfo &operator=(SourceFileSymbolInfo &&from) noexcept;

  void set_name(std::string_view name) noexcept;
  void set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept;
  void set_linetable(u64 line_table) noexcept;
  void set_id(SymbolInfoId id) noexcept;

  bool known_address_boundary() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;
  std::string_view name() const noexcept;
  bool function_symbols_resolved() const noexcept;
  sym::FunctionSymbol *get_fn_by_pc(AddrPtr pc) noexcept;
  dw::UnitData *get_dwarf_unit() const noexcept;
  std::optional<dw::LineTable> get_linetable() noexcept;
  static constexpr auto
  Sorter() noexcept
  {
    return AddressableSorter<SourceFileSymbolInfo, false>{};
  }

private:
  void resolve_fn_symbols() noexcept;
  void maybe_create_fn_symbol(StringOpt name, StringOpt mangled_name, AddrOpt low_pc, AddrOpt high_pc) noexcept;
};

class AddressToCompilationUnitMap
{
public:
  AddressToCompilationUnitMap() noexcept;
  std::vector<sym::dw::UnitData *> find_by_pc(AddrPtr pc) noexcept;
  void add_cus(const std::span<SourceFileSymbolInfo> &cus) noexcept;

private:
  void add_cu(AddrPtr start, AddrPtr end, sym::dw::UnitData *cu) noexcept;
  std::mutex mutex;
  utils::IntervalMapping<AddrPtr, sym::dw::UnitData *> mapping;
};

class SourceFileSymbolManager
{
  std::mutex m;
  std::vector<SourceFileSymbolInfo> source_units;
  ObjectFile *objfile;

public:
  SourceFileSymbolManager(ObjectFile *obj) noexcept;
  /*
   * Search and find what SourceFileSymbolInfo spans `pc`. This function will also pre-fetch data for the returned
   * info's, like building their Line Number Program table, by posting the work to the global thread pool.
   */
  std::vector<SourceFileSymbolInfo *> get_source_infos(AddrPtr pc) noexcept;
};
} // namespace sym