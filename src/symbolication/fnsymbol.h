#pragma once
#include "../common.h"
#include "addr_sorter.h"
#include "dwarf/die.h"
#include "symbolication/dwarf_expressions.h"
#include "symbolication/type.h"

namespace sym {
namespace dw {
class FunctionSymbolicationContext;
}
class SourceFileSymbolInfo;

struct ResolveFnSymbolState;

class FunctionSymbol
{
  // type that actually builds `FunctionSymbol`s and thus calls the constructor.
  friend ResolveFnSymbolState;
  // Type that fully realizes symbol information when it's needed during the debug session
  friend sym::dw::FunctionSymbolicationContext;
  SourceFileSymbolInfo *decl_file;
  bool fully_parsed;
  bool is_member_fn;
  SymbolBlock formal_parameters;
  std::vector<SymbolBlock> function_body_variables;
  Immutable<std::array<dw::IndexedDieReference, 3>> maybe_origin_dies;
  dw::FrameBaseExpression framebase_expr;

  FunctionSymbol(AddrPtr start, AddrPtr end, std::string_view name, std::string_view member_of,
                 std::array<dw::IndexedDieReference, 3> maybe_origin, SourceFileSymbolInfo *decl_file,
                 dw::FrameBaseExpression fb_expr) noexcept;

  void resolve_symbols() noexcept;

public:
  Immutable<AddrPtr> pc_start;
  Immutable<AddrPtr> pc_end_exclusive;
  Immutable<std::string_view> member_of;
  Immutable<std::string_view> name;

  const SymbolBlock &get_fn_parameters() noexcept;
  std::span<const SymbolBlock> get_function_variables() noexcept;

  std::string build_full_name() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;
  SourceFileSymbolInfo *symbol_info() const noexcept;
  std::span<const dw::IndexedDieReference> origin_dies() const noexcept;
  bool is_resolved() const noexcept;
  dw::FrameBaseExpression frame_base() const noexcept;

  const std::vector<Symbol> &get_args() const noexcept;

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