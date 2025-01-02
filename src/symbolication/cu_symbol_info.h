#pragma once
#include "./dwarf/lnp.h"
#include "fnsymbol.h"
#include "symbolication/block.h"
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
  friend class dw::SourceCodeFile;
  dw::UnitData *mUnitData;
  AddrPtr mPcStart{nullptr};
  AddrPtr mPcEndExclusive{nullptr};
  dw::LNPHeader* mLineNumberProgram{nullptr};
  std::vector<dw::LineTableEntry> mLineTable;
  std::string_view mCompilationUnitName;
  std::vector<sym::FunctionSymbol> mFunctionSymbols;
  std::vector<u32> imported_units;
  std::vector<AddressRange> mAddressRanges;

  // Indexed by their definitions in the Line Number Program Header, so no need for a map here.
  std::vector<std::shared_ptr<dw::SourceCodeFile>> mSourceCodeFiles{};
  mutable std::mutex m{};
  mutable bool computed{false};

public:
  NO_COPY(CompilationUnit);
  CompilationUnit& operator=(CompilationUnit&&) noexcept = delete;
  CompilationUnit(CompilationUnit&&) noexcept = delete;

  CompilationUnit(dw::UnitData *unitData) noexcept;

  void SetUnitName(std::string_view name) noexcept;
  void SetAddressRanges(std::vector<AddressRange>&& ranges) noexcept;
  void SetAddressBoundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept;
  void ProcessSourceCodeFiles(dw::LNPHeader* header) noexcept;
  bool LineTableComputed() noexcept;
  void ComputeLineTable() noexcept;
  std::span<const AddressRange> AddressRanges() const noexcept;
  std::span<const dw::LineTableEntry> GetLineTable() const noexcept;
  std::span<std::shared_ptr<dw::SourceCodeFile>> sources() noexcept;

  bool HasKnownAddressBoundary() const noexcept;
  AddrPtr StartPc() const noexcept;
  AddrPtr EndPc() const noexcept;
  std::string_view name() const noexcept;
  bool IsFunctionSymbolsResolved() const noexcept;
  sym::FunctionSymbol *GetFunctionSymbolByProgramCounter(AddrPtr pc) noexcept;
  dw::UnitData *get_dwarf_unit() const noexcept;
  std::optional<Path> get_lnp_file(u32 index) noexcept;
  static constexpr auto
  Sorter() noexcept
  {
    return AddressableSorter<CompilationUnit, false>{};
  }

  std::pair<dw::SourceCodeFile *, const dw::LineTableEntry *> GetLineTableEntry(AddrPtr unrelocatedAddress) noexcept;
  dw::SourceCodeFile* GetFileByLineProgramIndex(u32 index) noexcept;

private:
  void PrepareFunctionSymbols() noexcept;
};

class AddressToCompilationUnitMap
{
public:
  AddressToCompilationUnitMap() noexcept;
  std::vector<CompilationUnit *> find_by_pc(AddrPtr pc) noexcept;
  void add_cus(std::span<CompilationUnit*> cus) noexcept;

private:
  void add_cu(AddrPtr start, AddrPtr end, CompilationUnit *cu) noexcept;
  std::mutex mutex;
  utils::IntervalMapping<AddrPtr, CompilationUnit *> mapping;
};
} // namespace sym