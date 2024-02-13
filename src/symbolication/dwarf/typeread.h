#pragma once

#include "symbolication/dwarf/die.h"
#include "symbolication/type.h"

namespace sym {
class FunctionSymbol;
class Frame;
} // namespace sym

struct ObjectFile;

namespace sym::dw {

/** SymbolicationContext "kinds" are types that "fully" resolve the surface areas of some entity (a function, a
 * type). Notice the terminology "surface area" and fully resolving it. A type may have many layers of various sub
 * objects. A fully resolved type, is *not* one where every sub-type is also fully resolved: it only means that
 * it's entire surface area is understood, which means that resolving subobjects from that point on is possible.
 */

class FunctionSymbolicationContext
{
  ObjectFile &obj;
  sym::FunctionSymbol *fn_ctx;
  SymbolBlock params;
  std::vector<SymbolBlock> lexicalBlockStack;
  u32 frame_locals_count{0};

  void process_formal_param(DieReference cu_die) noexcept;
  void process_variable(DieReference cu_die) noexcept;
  void process_lexical_block(DieReference cu_die) noexcept;
  void process_inlined(DieReference cu_die) noexcept;
  NonNullPtr<Type> process_type(DieReference cu_die) noexcept;

public:
  explicit FunctionSymbolicationContext(ObjectFile &obj, sym::Frame &frame) noexcept;
  void process_symbol_information() noexcept;
};

class TypeSymbolicationContext
{
  ObjectFile &obj;
  std::vector<Field> type_fields;
  sym::Type *current_type;
  void process_member_variable(DieReference cu_die) noexcept;

public:
  TypeSymbolicationContext(ObjectFile &object_file, Type *type) noexcept;
  // Fully resolves `Type`
  void resolve_type() noexcept;
};

} // namespace sym::dw