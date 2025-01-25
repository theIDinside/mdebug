/** LICENSE TEMPLATE */
#pragma once
#include <symbolication/dwarf/die_ref.h>
#include <symbolication/type.h>

namespace sym {
class FunctionSymbol;
class Frame;
} // namespace sym

class ObjectFile;

namespace sym::dw {

/** SymbolicationContext "kinds" are types that "fully" resolve the surface areas of some entity (a function, a
 * type). Notice the terminology "surface area" and fully resolving it. A type may have many layers of various sub
 * objects. A fully resolved type, is *not* one where every sub-type is also fully resolved: it only means that
 * it's entire surface area is understood, which means that resolving subobjects from that point on is possible.
 */

class FunctionSymbolicationContext
{
  ObjectFile &mObjectRef;
  sym::FunctionSymbol *mFunctionSymbol;
  SymbolBlock mParams;
  std::vector<SymbolBlock> mLexicalBlockStack;
  u32 mFrameLocalsCount{0};

  // Process the variable DIE referenced by `variableDebugInfoEntry` and store it (if successful) in
  // `processedSymbolStack`
  bool ProcessVariableDie(DieReference variableDebugInfoEntry, std::vector<Symbol> &processedSymbolStack) noexcept;
  void ProcessVariable(DieReference dieRef) noexcept;
  void ProcessFormalParameter(DieReference die) noexcept;

  void ProcessLexicalBlockDie(DieReference die) noexcept;
  void ProcessInlinedSubroutineDie(DieReference die) noexcept;
  NonNullPtr<Type> ProcessTypeDie(DieReference die) noexcept;

public:
  explicit FunctionSymbolicationContext(ObjectFile &obj, sym::Frame &frame) noexcept;
  void ProcessSymbolInformation() noexcept;
};

class TypeSymbolicationContext
{
  ObjectFile &mObjectRef;
  std::vector<Field> mTypeFields;
  sym::Type *mCurrentType;

  sym::Type *mEnumerationType{nullptr};
  bool mEnumIsSigned{false};
  std::vector<EnumeratorConstValue> mConstValues{};
  void process_member_variable(DieReference die) noexcept;
  void ProcessInheritanceDie(DieReference die) noexcept;
  void ProcessEnumDie(DieReference die) noexcept;

public:
  TypeSymbolicationContext(ObjectFile &object_file, Type &type) noexcept;
  static TypeSymbolicationContext ContinueWith(const TypeSymbolicationContext &ctx, Type *t) noexcept;

  // Fully resolves `Type`
  void ResolveType() noexcept;
};

} // namespace sym::dw