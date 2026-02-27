/** LICENSE TEMPLATE */
#pragma once
#include <symbolication/dwarf/die_ref.h>
#include <symbolication/type.h>

namespace mdb {
class ObjectFile;
namespace sym {
class FunctionSymbol;
class Frame;
} // namespace sym
} // namespace mdb

namespace mdb::sym::dw {

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
  u32 mFrameLocalsCount{ 0 };

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

struct DieContextEntry
{
  DwarfTag mTag;
  DieReference mDie;
};

/** The DIE context for a type. Effectively it is the path from the DIE defininig the type up to the top-most
 * parent that is not a DWARF unit type */
class TypeDIEContext
{
  // goes from closest-to-mDie to root
  std::vector<DieContextEntry> mAncestorDies;
  void Reserve(size_t size);

  bool operator==(const TypeDIEContext &rhs) const;

public:
  void AppendDie(DieReference dieRef);
  static TypeDIEContext Create(DieReference dieRef);
  bool TypeContextMatches(const TypeDIEContext &other) const;
};

class TypeSymbolicationContext
{
  // The object file whose debug information we're parsing from
  ObjectFile &mObjectRef;

  // The currently built state for resolving the type we're building.
  std::vector<Field> mTypeFields;
  TemplateArguments mTemplateArguments;
  // The type being built
  sym::Type *mRequestedTypeDieToResolve;
  sym::Type *mEnumerationType{ nullptr };
  bool mEnumIsSigned{ false };
  std::vector<EnumeratorConstValue> mConstValues;

  void ProcessMemberVariable(DieReference die) noexcept;
  void ProcessInheritanceDie(DieReference die) noexcept;
  void ProcessEnumDie(DieReference die) noexcept;
  void ProcessTemplateParameter(DieReference die, bool isValue) noexcept;

  void ResolveDeclarationType(sym::Type *type);

public:
  TypeSymbolicationContext(ObjectFile &object_file, Type &type) noexcept;
  static TypeSymbolicationContext ContinueWith(const TypeSymbolicationContext &ctx, Type *t) noexcept;

  // Fully resolves `Type`
  void ResolveType() noexcept;
};

} // namespace mdb::sym::dw