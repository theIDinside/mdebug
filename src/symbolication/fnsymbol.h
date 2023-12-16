#pragma once
#include "../common.h"
#include "addr_sorter.h"
#include "dwarf/die.h"

namespace sym {
class SourceFileSymbolInfo;
struct FunctionSymbol
{
  AddrPtr pc_start = nullptr;
  AddrPtr pc_end_exclusive = nullptr;
  std::string_view member_of{};
  std::string_view name{};
  std::array<dw::IndexedDieReference, 3> maybe_origin_dies;
  SourceFileSymbolInfo *decl_file = nullptr;

  std::string build_full_name() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;

  friend bool is_same(const FunctionSymbol &l, const FunctionSymbol &r) noexcept;
  friend bool is_same(const FunctionSymbol *l, const FunctionSymbol *r) noexcept;
  static constexpr auto
  Sorter() noexcept
  {
    return AddressableSorter<FunctionSymbol, false>{};
  }

  static constexpr auto
  SortByStartPc()
  {
    return AddressableLowBoundSorter<FunctionSymbol>{};
  }
};

struct FunctionSymbolSearchResult
{
  FunctionSymbolSearchResult() noexcept;
  FunctionSymbolSearchResult(FunctionSymbol *fn) noexcept;
  FunctionSymbol &value() const noexcept;
  FunctionSymbol *operator->() const noexcept;
  FunctionSymbol &operator*() const noexcept;

  constexpr bool
  has_value() const noexcept
  {
    return fn != nullptr;
  }

private:
  FunctionSymbol *fn;
};
bool is_same(const FunctionSymbol &l, const FunctionSymbol &r) noexcept;
bool is_same(const FunctionSymbol *l, const FunctionSymbol *r) noexcept;
} // namespace sym

namespace fmt {

template <> struct formatter<sym::FunctionSymbol>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::FunctionSymbol &var, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "fn={}, [{} .. {}]", var.name, var.start_pc(), var.end_pc());
  }
};
} // namespace fmt