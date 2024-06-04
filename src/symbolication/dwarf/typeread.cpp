#include "typeread.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/die_iterator.h"
#include "symbolication/dwarf/die_ref.h"
#include "symbolication/dwarf_defs.h"
#include <atomic>
#include <symbolication/callstack.h>
#include <symbolication/objfile.h>

namespace sym::dw {

FunctionSymbolicationContext::FunctionSymbolicationContext(ObjectFile &obj, sym::Frame &frame) noexcept
    : obj(obj), fn_ctx(frame.maybe_get_full_symbols()),
      params{.entry_pc = fn_ctx->start_pc(), .end_pc = fn_ctx->end_pc(), .symbols = {}},
      lexicalBlockStack({params})
{
  ASSERT(lexicalBlockStack.size() == 1, "Expected block stack size == 1, was {}", lexicalBlockStack.size());
}

NonNullPtr<Type>
FunctionSymbolicationContext::process_type(DieReference cu_die) noexcept
{
  auto t = obj.types->get_or_prepare_new_type(cu_die.as_indexed());
  if (t == nullptr) {
    PANIC("Failed to get or prepare new type to be realized");
  }
  return NonNull(*t);
}

void
FunctionSymbolicationContext::process_lexical_block(DieReference cu_die) noexcept
{
  AddrPtr low = nullptr, hi = nullptr;
  const auto block_seen = [&]() { return low != nullptr && hi != nullptr; };
  auto &attr = cu_die.cu->get_abbreviation(cu_die.die->abbreviation_code);
  UnitReader reader{cu_die.cu};
  reader.seek_die(*cu_die.die);

  for (const auto abbr : attr.attributes) {
    auto value = read_attribute_value(reader, abbr, attr.implicit_consts);
    if (value.name == Attribute::DW_AT_low_pc || value.name == Attribute::DW_AT_entry_pc) {
      low = value.address();
    }
    if (value.name == Attribute::DW_AT_high_pc) {
      hi = value.address();
    }
    if (block_seen()) {
      break;
    }
  }
  lexicalBlockStack.emplace_back(low, low + hi, std::vector<Symbol>{});
}

void
FunctionSymbolicationContext::process_inlined(DieReference cu_die) noexcept
{
  DBGLOG(core, "[symbolication]: process_inline not implemented (cu={}, die={})", cu_die.cu->section_offset(),
         cu_die.die->section_offset);
}

void
FunctionSymbolicationContext::process_variable(DieReference cu_die) noexcept
{

  const auto location = cu_die.read_attribute(Attribute::DW_AT_location);
  const auto name = cu_die.read_attribute(Attribute::DW_AT_name);
  const auto type_id = cu_die.read_attribute(Attribute::DW_AT_type);

  ASSERT(location, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
         "loclistx location descriptors not supported yet. cu=0x{:x}, die=0x{:x}", cu_die.cu->section_offset(),
         cu_die.die->section_offset);
  ASSERT(name, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  ASSERT(type_id, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  auto containing_cu_die_ref = obj.get_die_reference(type_id->unsigned_value());
  ASSERT(containing_cu_die_ref.has_value(), "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
         type_id->unsigned_value());

  auto type = process_type(containing_cu_die_ref.value());
  DataBlock dwarf_expr_block = location->block();
  std::span<const u8> expr{dwarf_expr_block.ptr, dwarf_expr_block.size};
  lexicalBlockStack.back().symbols.emplace_back(type, SymbolLocation::Expression(expr), name->string());
}

void
FunctionSymbolicationContext::process_formal_param(DieReference cu_die) noexcept
{

  const auto location = cu_die.read_attribute(Attribute::DW_AT_location);
  const auto name = cu_die.read_attribute(Attribute::DW_AT_name);
  const auto type_id = cu_die.read_attribute(Attribute::DW_AT_type);

  ASSERT(location, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
         "loclistx location descriptors not supported yet. cu=0x{:x}, die=0x{:x}", cu_die.cu->section_offset(),
         cu_die.die->section_offset);
  ASSERT(name, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  ASSERT(type_id, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));

  auto containing_cu_die_ref = obj.get_die_reference(type_id->unsigned_value());
  ASSERT(containing_cu_die_ref.has_value(), "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
         type_id->unsigned_value());

  auto type = process_type(*containing_cu_die_ref);
  DataBlock dwarf_expr_block = location->block();
  std::span<const u8> expr{dwarf_expr_block.ptr, dwarf_expr_block.size};
  params.symbols.emplace_back(type, SymbolLocation::Expression(expr), name->string());
}

void
FunctionSymbolicationContext::process_symbol_information() noexcept
{
  if (fn_ctx->is_resolved()) {
    return;
  }

  const auto &dies = fn_ctx->origin_dies();
  for (const auto [cu, die_index] : dies) {
    auto cu_die_ref = cu->get_cu_die_ref(die_index);
    ASSERT(cu_die_ref.die->tag == DwarfTag::DW_TAG_subprogram, "Origin die for a fn wasn't subprogram! It was: {}",
           to_str(cu_die_ref.die->tag));

    auto die_it = cu_die_ref.die->children();
    // Means this fn ctx has no children. Whatever meta data (like pc start, pc end, etc) we may have, must already
    // have been processed.
    if (die_it == nullptr) {
      return;
    }
    const auto parent = cu_die_ref.die;
    const auto next = [&parent](auto curr, auto next) {
      if (next) {
        return next;
      } else {
        auto test = curr->parent();
        while (!test->sibling() && test != parent) {
          test = test->parent();
        }
        return (test == parent) ? parent : test->sibling();
      }
    };

    while (die_it != parent) {
      switch (die_it->tag) {
      case DwarfTag::DW_TAG_formal_parameter: {
        process_formal_param(DieReference{cu_die_ref.cu, die_it});
        die_it = next(die_it, die_it->sibling());
      } break;
      case DwarfTag::DW_TAG_variable:
        ++frame_locals_count;
        process_variable(DieReference{cu_die_ref.cu, die_it});
        die_it = next(die_it, die_it->sibling());
        break;
      case DwarfTag::DW_TAG_lexical_block:
        process_lexical_block(DieReference{cu_die_ref.cu, die_it});
        die_it = next(die_it, die_it->children());
        break;
      case DwarfTag::DW_TAG_inlined_subroutine:
        process_inlined(DieReference{cu_die_ref.cu, die_it});
        die_it = next(die_it, die_it->children());
        break;
      default:
        DBGLOG(core, "[WARNING]: Unexpected Tag in subprorogram die: {}", to_str(die_it->tag));
      }
    }
  }
  std::swap(fn_ctx->formal_parameters, params);
  std::swap(fn_ctx->function_body_variables, lexicalBlockStack);
  fn_ctx->frame_locals_count = frame_locals_count;
  fn_ctx->fully_parsed = true;
}

TypeSymbolicationContext::TypeSymbolicationContext(ObjectFile &object_file, Type &type) noexcept
    : obj(object_file), current_type(&type)
{
}

TypeSymbolicationContext
TypeSymbolicationContext::continueWith(const TypeSymbolicationContext &ctx, Type *t) noexcept
{
  return TypeSymbolicationContext{ctx.obj, *t};
}

// Fully resolves `Type`

void
TypeSymbolicationContext::process_inheritance(DieReference cu_die) noexcept
{
  const auto location = cu_die.read_attribute(Attribute::DW_AT_data_member_location);
  const auto type_id = cu_die.read_attribute(Attribute::DW_AT_type);

  auto containing_cu_die_ref = obj.get_die_reference(type_id->unsigned_value());
  auto type = obj.types->get_or_prepare_new_type(containing_cu_die_ref->as_indexed());
  auto ctx = TypeSymbolicationContext::continueWith(*this, type);
  ctx.resolve_type();

  if (!type->fields.empty()) {
    const auto member_offset = location->unsigned_value();
    for (auto t : type->fields) {
      type_fields.push_back(Field{.type = t.type, .offset_of = *t.offset_of + member_offset, .name = t.name});
    }
  }
}

void
TypeSymbolicationContext::process_member_variable(DieReference cu_die) noexcept
{

  const auto location = cu_die.read_attribute(Attribute::DW_AT_data_member_location);
  const auto name = cu_die.read_attribute(Attribute::DW_AT_name);
  const auto type_id = cu_die.read_attribute(Attribute::DW_AT_type);

  // A member without a location is not a member. It can be a static variable or a constexpr variable.
  if (!location) {
    DBGLOG(core, "die 0x{:x} (name={}) is DW_TAG_member but had no location (static/constexpr/static-constexpr?)",
           cu_die.die->section_offset,
           name.transform([](auto v) { return v.string(); }).value_or("die had no name"));
    return;
  }

  ASSERT(location, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
         "loclistx location descriptors not supported yet. cu=0x{:x}, die=0x{:x}", cu_die.cu->section_offset(),
         cu_die.die->section_offset);
  ASSERT(name, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));
  ASSERT(type_id, "Expected to find location attribute for die 0x{:x} ({})", cu_die.die->section_offset,
         to_str(cu_die.die->tag));

  auto containing_cu_die_ref = obj.get_die_reference(type_id->unsigned_value());
  ASSERT(containing_cu_die_ref.has_value(),
         "Failed to get compilation unit & die reference from DIE offset: 0x{:x}", type_id->unsigned_value());

  auto type = obj.types->get_or_prepare_new_type(containing_cu_die_ref->as_indexed());
  const auto member_offset = location->unsigned_value();
  this->type_fields.push_back(Field{.type = NonNull(*type), .offset_of = member_offset, .name = name->string()});
}

void
TypeSymbolicationContext::process_enum(DieReference cu_die) noexcept
{
  const auto name = cu_die.read_attribute(Attribute::DW_AT_name);
  const auto member_offset = cu_die.read_attribute(Attribute::DW_AT_data_member_location)
                               .transform([](auto v) { return v.unsigned_value(); })
                               .value_or(0);
  const auto const_value = cu_die.read_attribute(Attribute::DW_AT_const_value);
  if (const_value) {
    enum_is_signed = const_value->form == AttributeForm::DW_FORM_sdata;
    if (enum_is_signed) {
      const_values.push_back(EnumeratorConstValue{.i = const_value->signed_value()});
    } else {
      const_values.push_back(EnumeratorConstValue{.u = const_value->unsigned_value()});
    }
  }

  this->type_fields.push_back(
    Field{.type = NonNull(*enumeration_type), .offset_of = member_offset, .name = name->string()});
}

void
TypeSymbolicationContext::resolve_type() noexcept
{
  auto type_iter = current_type;
  while (type_iter != nullptr) {
    if (type_iter->resolved) {
      type_iter = type_iter->type_chain;
      continue;
    }
    auto cu = type_iter->cu_die_ref->cu;
    auto die = type_iter->cu_die_ref.mut().get_die();
    auto typedie = DieReference{cu, die};
    if (die->tag == DwarfTag::DW_TAG_enumeration_type) {
      const auto type_id = typedie.read_attribute(Attribute::DW_AT_type);
      if (type_id) {
        auto containing_cu_die_ref = obj.get_die_reference(type_id->unsigned_value());
        enumeration_type = obj.types->get_or_prepare_new_type(containing_cu_die_ref->as_indexed());
      }
    }

    die = die->children();
    for (const auto die : sym::dw::IterateSiblings{cu, die}) {
      switch (die.tag) {
      case DwarfTag::DW_TAG_member:
        process_member_variable(DieReference{cu, &die});
        break;
      case DwarfTag::DW_TAG_inheritance:
        process_inheritance(DieReference{cu, &die});
        break;
      case DwarfTag::DW_TAG_enumerator:
        process_enum(DieReference{cu, &die});
        break;
      default:
        continue;
      }
    }

    if (typedie.die->tag == DwarfTag::DW_TAG_enumeration_type) {
      type_iter->enum_values = {.is_signed = enum_is_signed,
                                .e_values = std::make_unique<EnumeratorConstValue[]>(type_fields.size())};
      std::copy(const_values.begin(), const_values.end(), type_iter->enum_values.e_values.get());
    }

    if (!type_fields.empty()) {
      std::swap(type_iter->fields, this->type_fields);
    }
    type_iter->resolved = true;
    type_iter = type_iter->type_chain;
  }
}

} // namespace sym::dw