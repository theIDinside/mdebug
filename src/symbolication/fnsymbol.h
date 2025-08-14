/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "addr_sorter.h"
#include "symbolication/type.h"
#include "utils/immutable.h"

namespace mdb::sym {
namespace dw {
class FunctionSymbolicationContext;
}
class CompilationUnit;

struct ResolveFnSymbolState;

enum class ReturnValueClass
{
  ImplicitPointerToMemory,
  RaxRdxPair,
  XmmRaxRdx,
  Unknown
};

ReturnValueClass DetermineArchitectureReturnClass(sym::Type *type) noexcept;

class FunctionSymbol
{
public:
  NO_COPY(FunctionSymbol);

private:
  // type that actually builds `FunctionSymbol`s and thus calls the constructor.
  friend ResolveFnSymbolState;
  friend sym::dw::FunctionSymbolicationContext;

  // Private members
  NonNullPtr<CompilationUnit> mDeclaringCompilationUnit;
  bool mFullyParsed{ false };
  bool mIsMethod{ false };
  u32 mFrameLocalVariableCount{ 0 };
  SymbolBlock mFormalParametersBlock;
  std::vector<SymbolBlock> mFunctionSymbolBlocks;
  Immutable<std::array<dw::IndexedDieReference, 3>> mMaybeOriginDies;
  std::span<const u8> mFrameBaseDwarfExpression;
  sym::Type *mFunctionReturnType;

  // Private member functions
  FunctionSymbol(AddrPtr start,
    AddrPtr end,
    std::string_view name,
    std::string_view member_of,
    sym::Type *return_type,
    std::array<dw::IndexedDieReference, 3> maybe_origin,
    CompilationUnit &decl_file,
    std::span<const u8> fb_expr,
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

  AddrPtr StartPc() const noexcept;
  AddrPtr EndPc() const noexcept;
  CompilationUnit *GetCompilationUnit() noexcept;
  std::span<const dw::IndexedDieReference> OriginDebugInfoEntries() const noexcept;
  bool IsResolved() const noexcept;
  std::span<const u8> GetFrameBaseDwarfExpression() const noexcept;

  const SymbolBlock &GetFunctionArguments() const noexcept;
  const std::vector<SymbolBlock> &GetFrameLocalVariableBlocks() const noexcept;
  u32 FrameVariablesCount() const noexcept;

  friend bool IsSame(const FunctionSymbol &l, const FunctionSymbol &r) noexcept;
  friend bool IsSame(const FunctionSymbol *l, const FunctionSymbol *r) noexcept;
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
bool IsSame(const FunctionSymbol &l, const FunctionSymbol &r) noexcept;
bool IsSame(const FunctionSymbol *l, const FunctionSymbol *r) noexcept;
} // namespace mdb::sym

template <> struct std::formatter<sym::FunctionSymbol>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const sym::FunctionSymbol &var, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(), "fn={}, [{} .. {}]", var.name, var.StartPc(), var.EndPc());
  }
};