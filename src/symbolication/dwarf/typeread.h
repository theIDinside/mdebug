#pragma once

#include "symbolication/dwarf/die.h"
#include "symbolication/type.h"
#include <unordered_set>

namespace sym {
class FunctionSymbol;
class Frame;
} // namespace sym

struct ObjectFile;

namespace sym::dw {

class FunctionSymbolicationContext
{
  ObjectFile *obj;
  sym::FunctionSymbol *fn_ctx;
  SymbolBlock params;
  std::vector<SymbolBlock> lexicalBlockStack;
  // prevent infinite recursion
  std::unordered_set<u64> types_in_flight{};

  void process_formal_param(UnitData *cu, const DieMetaData *die) noexcept;
  void process_variable(UnitData *cu, const DieMetaData *die) noexcept;
  void process_lexical_block(UnitData *cu, const DieMetaData *die) noexcept;
  void process_inlined(UnitData *cu, const DieMetaData *die) noexcept;
  NonNullPtr<Type> process_type(UnitData *cu, const DieMetaData *die) noexcept;

public:
  explicit FunctionSymbolicationContext(ObjectFile *obj, sym::Frame &frame) noexcept;
  void process_symbol_information() noexcept;
};

sym::Type *prepare_structured_type(ObjectFile *obj, IndexedDieReference cu_die) noexcept;
void process_types(FunctionSymbolicationContext *ctx, dw::DieReference die_ref) noexcept;

} // namespace sym::dw