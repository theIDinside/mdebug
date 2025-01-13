/** LICENSE TEMPLATE */
#include "fnsymbol.h"
namespace sym {

ReturnValueClass
DetermineArchitectureReturnClass(sym::Type *type) noexcept
{
  if (type->Size() > 16) {
    return ReturnValueClass::ImplicitPointerToMemory;
  }
  return ReturnValueClass::Unknown;
}

FunctionSymbol::FunctionSymbol(AddrPtr start, AddrPtr end, std::string_view name, std::string_view member_of,
                               sym::Type *return_type, std::array<dw::IndexedDieReference, 3> maybe_origin,
                               CompilationUnit &decl_file, std::span<const u8> fb_expr,
                               std::optional<SourceCoordinate> &&source) noexcept
    : mDeclaringCompilationUnit(NonNull(decl_file)), mFormalParametersBlock({start, end}, {}), mFunctionSymbolBlocks(),
      mMaybeOriginDies(maybe_origin), mFrameBaseDwarfExpression(fb_expr), mFunctionReturnType(return_type), pc_start(start),
      pc_end_exclusive(end), member_of(member_of), name(name), source(std::move(source))
{
}

FunctionSymbol::FunctionSymbol(FunctionSymbol &&fn) noexcept
    : mDeclaringCompilationUnit(fn.mDeclaringCompilationUnit), mFormalParametersBlock(std::move(fn.mFormalParametersBlock)),
      mFunctionSymbolBlocks(std::move(fn.mFunctionSymbolBlocks)),
      mMaybeOriginDies(fn.mMaybeOriginDies), mFrameBaseDwarfExpression(fn.mFrameBaseDwarfExpression),
      mFunctionReturnType(fn.mFunctionReturnType), pc_start(fn.pc_start), pc_end_exclusive(fn.pc_end_exclusive),
      member_of(fn.member_of), name(fn.name), source(std::move(fn.source))
{
}

AddrPtr
FunctionSymbol::StartPc() const noexcept
{
  return pc_start;
}
AddrPtr
FunctionSymbol::EndPc() const noexcept
{
  return pc_end_exclusive;
}

CompilationUnit *
FunctionSymbol::GetCompilationUnit() noexcept
{
  return mDeclaringCompilationUnit;
}

std::span<const dw::IndexedDieReference>
FunctionSymbol::OriginDebugInfoEntries() const noexcept
{
  auto &dies = *mMaybeOriginDies;
  for (auto i = 0u; i < dies.size(); ++i) {
    if (!dies[i].IsValid()) {
      return std::span{dies.begin(), dies.begin() + i};
    }
  }
  return dies;
}

bool
FunctionSymbol::IsResolved() const noexcept
{
  return mFullyParsed;
}

std::span<const u8>
FunctionSymbol::GetFrameBaseDwarfExpression() const noexcept
{
  return mFrameBaseDwarfExpression;
}

const SymbolBlock &
FunctionSymbol::GetFunctionArguments() const noexcept
{
  return mFormalParametersBlock;
}

const std::vector<SymbolBlock> &
FunctionSymbol::GetFrameLocalVariableBlocks() const noexcept
{
  return mFunctionSymbolBlocks;
}

u32
FunctionSymbol::FrameVariablesCount() const noexcept
{
  return mFrameLocalVariableCount;
}

FunctionSymbolSearchResult::FunctionSymbolSearchResult() noexcept : fn(nullptr) {}

FunctionSymbolSearchResult::FunctionSymbolSearchResult(FunctionSymbol *fn) noexcept : fn(fn) {}

FunctionSymbol &
FunctionSymbolSearchResult::value() const noexcept
{
  ASSERT(has_value(), "Search result had no value");
  return *fn;
}

FunctionSymbol *
FunctionSymbolSearchResult::operator->() const noexcept
{
  ASSERT(has_value(), "Search result had no value");
  return fn;
}

FunctionSymbol &
FunctionSymbolSearchResult::operator*() const noexcept
{
  return value();
}

bool
IsSame(const FunctionSymbol *l, const FunctionSymbol *r) noexcept
{
  if (!l || !r) {
    return false;
  }
  return IsSame(*l, *r);
}

bool
IsSame(const FunctionSymbol &l, const FunctionSymbol &r) noexcept
{
  return *l.name == *r.name && *l.pc_start == *r.pc_start && *l.pc_end_exclusive == *r.pc_end_exclusive;
}

} // namespace sym