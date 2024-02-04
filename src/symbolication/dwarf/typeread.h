#pragma once

#include "symbolication/type.h"

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
  u32 frame_locals_count{0};

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

class TypeSymbolicationContext
{
  ObjectFile *obj;
  std::vector<Field> type_fields;
  sym::Type *current_type;
  void process_member_variable(UnitData *cu, const DieMetaData *die) noexcept;

public:
  TypeSymbolicationContext(ObjectFile &object_file, Type *type) noexcept;
  // Fully resolves `Type`
  void resolve_type() noexcept;
};

} // namespace sym::dw