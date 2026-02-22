/** LICENSE TEMPLATE */
#include "fnsymbol.h"
namespace mdb::sym {

ReturnValueClass
DetermineArchitectureReturnClass(sym::Type *type) noexcept
{
  if (type->Size() > 16) {
    return ReturnValueClass::ImplicitPointerToMemory;
  }
  return ReturnValueClass::Unknown;
}

FunctionSymbol::FunctionSymbol(AddrPtr start,
  AddrPtr end,
  std::string_view name,
  std::string_view memberOf,
  sym::Type *returnType,
  std::array<dw::IndexedDieReference, 3> maybeOrigin,
  CompilationUnit &declFile,
  std::span<const u8> fbExpr,
  std::optional<SourceCoordinate> &&source) noexcept
    : mDeclaringCompilationUnit(NonNull(declFile)), mFormalParametersBlock({ { start, end } }, {}),
      mMaybeOriginDies(maybeOrigin), mFrameBaseDwarfExpression(fbExpr), mFunctionReturnType(returnType),
      mStartPc(start), mExclusiveEndPc(end), mMemberOf(memberOf), mName(name), mSource(std::move(source))
{
}

FunctionSymbol::FunctionSymbol(FunctionSymbol &&fn) noexcept
    : mDeclaringCompilationUnit(fn.mDeclaringCompilationUnit),
      mFormalParametersBlock(std::move(fn.mFormalParametersBlock)),
      mFunctionSymbolBlocks(std::move(fn.mFunctionSymbolBlocks)), mMaybeOriginDies(fn.mMaybeOriginDies),
      mFrameBaseDwarfExpression(fn.mFrameBaseDwarfExpression), mFunctionReturnType(fn.mFunctionReturnType),
      mStartPc(fn.mStartPc), mExclusiveEndPc(fn.mExclusiveEndPc), mMemberOf(fn.mMemberOf), mName(fn.mName),
      mSource(std::move(fn.mSource))
{
}

AddrPtr
FunctionSymbol::StartPc() const noexcept
{
  return *mStartPc;
}

AddrPtr
FunctionSymbol::EndPc() const noexcept
{
  return *mExclusiveEndPc;
}

CompilationUnit *
FunctionSymbol::GetCompilationUnit() noexcept
{
  return mDeclaringCompilationUnit;
}

std::span<const dw::IndexedDieReference>
FunctionSymbol::OriginDebugInfoEntries() const noexcept
{
  for (size_t i = 0; i < mMaybeOriginDies->size(); ++i) {
    if (!mMaybeOriginDies[i].IsValid()) {
      return std::span{ mMaybeOriginDies->begin(), mMaybeOriginDies->begin() + i };
    }
  }
  return mMaybeOriginDies;
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
  MDB_ASSERT(has_value(), "Search result had no value");
  return *fn;
}

FunctionSymbol *
FunctionSymbolSearchResult::operator->() const noexcept
{
  MDB_ASSERT(has_value(), "Search result had no value");
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
  return *l.mName == *r.mName && *l.mStartPc == *r.mStartPc && *l.mExclusiveEndPc == *r.mExclusiveEndPc;
}

} // namespace mdb::sym