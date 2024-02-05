#include "typeread.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf/die.h"
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
    if (block_seen())
      break;
  }
  lexicalBlockStack.emplace_back(low, low + hi, std::vector<Symbol>{});
}

void
FunctionSymbolicationContext::process_inlined(DieReference cu_die) noexcept
{
  DLOG("mdb", "[symbolication]: process_inline not implemented (cu={}, die={})", cu_die.cu->section_offset(),
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
  if (fn_ctx->is_resolved())
    return;

  const auto &dies = fn_ctx->origin_dies();
  for (const auto [cu, die_index] : dies) {
    auto cu_die_ref = cu->get_cu_die_ref(die_index);
    ASSERT(cu_die_ref.die->tag == DwarfTag::DW_TAG_subprogram, "Origin die for a fn wasn't subprogram! It was: {}",
           to_str(cu_die_ref.die->tag));

    auto die_it = cu_die_ref.die->children();
    const auto parent = cu_die_ref.die;
    const auto next = [&parent](auto curr, auto next) {
      if (next)
        return next;
      else {
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
        DLOG("mdb", "[WARNING]: Unexpected Tag in subprorogram die: {}", to_str(die_it->tag));
      }
    }
  }
  std::swap(fn_ctx->formal_parameters, params);
  std::swap(fn_ctx->function_body_variables, lexicalBlockStack);
  fn_ctx->frame_locals_count = frame_locals_count;
  fn_ctx->fully_parsed = true;
}

TypeSymbolicationContext::TypeSymbolicationContext(ObjectFile &object_file, Type *type) noexcept
    : obj(object_file), current_type(type)
{
}
// Fully resolves `Type`

void
TypeSymbolicationContext::process_member_variable(DieReference cu_die) noexcept
{

  const auto location = cu_die.read_attribute(Attribute::DW_AT_data_member_location);
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
  ASSERT(containing_cu_die_ref.has_value(),
         "Failed to get compilation unit & die reference from DIE offset: 0x{:x}", type_id->unsigned_value());

  auto type = obj.types->get_or_prepare_new_type(containing_cu_die_ref->as_indexed());
  const auto member_offset = location->unsigned_value();
  this->type_fields.push_back(Field{.type = NonNull(*type), .offset_of = member_offset, .name = name->string()});
}

void
TypeSymbolicationContext::resolve_type() noexcept
{
  auto cu = current_type->cu_die_ref->cu;
  auto die = current_type->cu_die_ref.mut().get_die();
  auto end = die->sibling();
  die = die->children();
  // pointers! Yay! F#&/ an iterator.
  while (die < end && die != nullptr) {
    switch (die->tag) {
    case DwarfTag::DW_TAG_member:
      process_member_variable(DieReference{cu, die});
      die = die->sibling();
      break;
    default:
      continue;
    }
  }
  std::swap(current_type->fields, this->type_fields);
  current_type->resolved = true;
}

} // namespace sym::dw