#pragma once
#include "../common.h"
#include "addr_sorter.h"
#include "symbolication/dwarf_expressions.h"
#include "symbolication/type.h"
#include "utils/immutable.h"

namespace sym {
namespace dw {
class FunctionSymbolicationContext;
}
class SourceFileSymbolInfo;

struct ResolveFnSymbolState;

enum class ReturnValueClass
{
  ImplicitPointerToMemory,
  RaxRdxPair,
  XmmRaxRdx,
  Unknown
};

ReturnValueClass determine_ret_class(sym::Type *type) noexcept;

class FunctionSymbol
{
public:
  NO_COPY(FunctionSymbol);

private:
  // type that actually builds `FunctionSymbol`s and thus calls the constructor.
  friend ResolveFnSymbolState;
  friend sym::dw::FunctionSymbolicationContext;

  // Private members
  NonNullPtr<SourceFileSymbolInfo> decl_file;
  bool fully_parsed{false};
  bool is_member_fn{false};
  u32 frame_locals_count{0};
  SymbolBlock formal_parameters;
  std::vector<SymbolBlock> function_body_variables;
  Immutable<std::array<dw::IndexedDieReference, 3>> maybe_origin_dies;
  dw::FrameBaseExpression framebase_expr;
  sym::Type *return_type;

  // Private member functions
  FunctionSymbol(AddrPtr start, AddrPtr end, std::string_view name, std::string_view member_of,
                 sym::Type *return_type, std::array<dw::IndexedDieReference, 3> maybe_origin,
                 SourceFileSymbolInfo &decl_file, dw::FrameBaseExpression fb_expr,
                 std::optional<SourceCoordinate> &&source_coord) noexcept;

public:
  // Only really used when constructing the full function symbols for a compilation unit, as std::vector grows, it
  // needs to move elements around. This is so UGH, at the same time it's just *SO* C++. Built-in, destructive
  // moves for the win, anybody?
  FunctionSymbol(FunctionSymbol &&fn) noexcept;
  FunctionSymbol &operator=(FunctionSymbol &&fn) noexcept = default;

  Immutable<AddrPtr> pc_start;
  Immutable<AddrPtr> pc_end_exclusive;
  Immutable<std::string_view> member_of;
  Immutable<std::string_view> name;
  Immutable<std::optional<SourceCoordinate>> source;

  std::string build_full_name() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;
  SourceFileSymbolInfo *symbol_info() noexcept;
  const SourceFileSymbolInfo *symbol_info() const noexcept;
  std::span<const dw::IndexedDieReference> origin_dies() const noexcept;
  bool is_resolved() const noexcept;
  dw::FrameBaseExpression frame_base() const noexcept;

  const SymbolBlock &get_args() const noexcept;
  const std::vector<SymbolBlock> &get_frame_locals() const noexcept;
  u32 local_variable_count() const noexcept;

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