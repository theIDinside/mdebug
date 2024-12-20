#pragma once
#include "./dwarf/lnp.h"
#include "fnsymbol.h"
#include "utils/interval_map.h"
#include <common.h>
#include <optional>

using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;

class ObjectFile;
class SymbolFile;
namespace sym {
namespace dw {
class UnitData;
}

class PartialCompilationUnitSymbolInfo
{
  dw::UnitData *unit_data;
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

class CompilationUnit
{
  dw::UnitData *unit_data;
  AddrPtr pc_start;
  AddrPtr pc_end_exclusive;
  u64 line_table;
  std::string_view cu_name;
  std::vector<sym::FunctionSymbol> fns;
  std::vector<u32> imported_units;
  std::vector<std::shared_ptr<dw::SourceCodeFile>> source_code_files{};

public:
  NO_COPY_DEFAULTED_MOVE(CompilationUnit);
  CompilationUnit(dw::UnitData *cu_data) noexcept;

  void set_name(std::string_view name) noexcept;
  void set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept;
  void ProcessSourceCodeFiles(u64 line_table) noexcept;
  void add_source_file(std::shared_ptr<dw::SourceCodeFile> &&src_file) noexcept;
  std::span<const std::shared_ptr<dw::SourceCodeFile>> sources() const noexcept;

  bool known_address_boundary() const noexcept;
  AddrPtr StartPc() const noexcept;
  AddrPtr EndPc() const noexcept;
  std::string_view name() const noexcept;
  bool function_symbols_resolved() const noexcept;
  sym::FunctionSymbol *get_fn_by_pc(AddrPtr pc) noexcept;
  dw::UnitData *get_dwarf_unit() const noexcept;
  std::optional<Path> get_lnp_file(u32 index) noexcept;
  static constexpr auto
  Sorter() noexcept
  {
    return AddressableSorter<CompilationUnit, false>{};
  }

private:
  void resolve_fn_symbols() noexcept;
};

class AddressToCompilationUnitMap
{
public:
  AddressToCompilationUnitMap() noexcept;
  std::vector<sym::dw::UnitData *> find_by_pc(AddrPtr pc) noexcept;
  void add_cus(const std::span<CompilationUnit> &cus) noexcept;

private:
  void add_cu(AddrPtr start, AddrPtr end, sym::dw::UnitData *cu) noexcept;
  std::mutex mutex;
  utils::IntervalMapping<AddrPtr, sym::dw::UnitData *> mapping;
};
} // namespace sym