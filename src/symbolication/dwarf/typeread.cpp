/** LICENSE TEMPLATE */
#include "typeread.h"
#include "symbolication/block.h"
#include "symbolication/dwarf.h"
#include "symbolication/dwarf/attribute_read.h"
#include "symbolication/dwarf/die_iterator.h"
#include "symbolication/dwarf_defs.h"
#include "symbolication/type.h"
#include "utils/logger.h"
#include <symbolication/callstack.h>
#include <symbolication/objfile.h>

namespace sym::dw {

FunctionSymbolicationContext::FunctionSymbolicationContext(ObjectFile &obj, sym::Frame &frame) noexcept
    : obj(obj), mFunctionSymbol(frame.MaybeGetFullSymbolInfo()),
      params{{mFunctionSymbol->StartPc(), mFunctionSymbol->EndPc()}, {}}, lexicalBlockStack()
{
  lexicalBlockStack.emplace_back(AddressRange{mFunctionSymbol->StartPc(), mFunctionSymbol->EndPc()},
                                 std::vector<Symbol>{});
  ASSERT(lexicalBlockStack.size() == 1, "Expected block stack size == 1, was {}", lexicalBlockStack.size());
  MUST_HOLD(mFunctionSymbol != nullptr,
            "To parse symbol information for a function, there must exist symbol information to parse.");
}

NonNullPtr<Type>
FunctionSymbolicationContext::process_type(DieReference cu_die) noexcept
{
  auto t = obj.GetTypeStorage()->GetOrCreateNewType(cu_die.AsIndexed());
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
  auto &attr = cu_die.GetUnitData()->get_abbreviation(cu_die.GetDie()->abbreviation_code);
  UnitReader reader{cu_die.GetUnitData()};
  reader.SeekDie(*cu_die.GetDie());

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
  lexicalBlockStack.emplace_back(AddressRange{low, low + hi}, std::vector<Symbol>{});
}

void
FunctionSymbolicationContext::ProcessInlinedSubroutine(DieReference cu_die) noexcept
{
  DBGLOG(core, "[symbolication]: process_inline not implemented (cu={}, die={})",
         cu_die.GetUnitData()->SectionOffset(), cu_die.GetDie()->section_offset);
}

struct ParseState
{
  using Data = std::optional<AttributeValue>;
  Data mLocation;
  Data mName;
  Data mTypeId;
  std::optional<DieReference> mReferedDie{};
  DieAttributeRead mProceed{DieAttributeRead::Skipped};

  constexpr bool
  ParsedEnough() const noexcept
  {
    return (mLocation && mName && mTypeId);
  }

  DieAttributeRead
  Proceed()
  {
    return DieAttributeRead::Continue;
  }
};

bool
FunctionSymbolicationContext::ProcessVariableDie(DieReference dieRef,
                                                 std::vector<Symbol> &processedSymbolStack) noexcept
{
  ParseState state;
  const auto originDie = dieRef;
  for (;;) {
    sym::dw::ProcessDie(
      dieRef, [&state, &dieRef](UnitReader &reader, Abbreviation &abbreviation, const AbbreviationInfo &info) {
        switch (abbreviation.name) {
        case Attribute::DW_AT_location:
          state.mLocation = read_attribute_value(reader, abbreviation, info.implicit_consts);
          return state.ParsedEnough() ? DieAttributeRead::Done : DieAttributeRead::Continue;
        case Attribute::DW_AT_name:
          state.mName = read_attribute_value(reader, abbreviation, info.implicit_consts);
          return state.ParsedEnough() ? DieAttributeRead::Done : DieAttributeRead::Continue;
        case Attribute::DW_AT_type:
          state.mTypeId = read_attribute_value(reader, abbreviation, info.implicit_consts);
          return state.ParsedEnough() ? DieAttributeRead::Done : DieAttributeRead::Continue;
        case Attribute::DW_AT_abstract_origin:
          [[fallthrough]];
        case Attribute::DW_AT_specification: {
          auto refereeValue = read_attribute_value(reader, abbreviation, info.implicit_consts);
          const auto declaring_die_offset = refereeValue.unsigned_value();
          state.mReferedDie =
            dieRef.GetUnitData()->GetObjectFile()->GetDebugInfoEntryReference(declaring_die_offset);
          return DieAttributeRead::Continue;
        }
        default:
          return DieAttributeRead::Skipped;
        }
      });
    if (state.ParsedEnough()) {
      break;
    } else {
      if (!state.mReferedDie) {
        DBGLOG(dwarf,
               "[ProcessVariableDie]: Ignoring DW_TAG_variable die, incomplete symbol information. die=0x{:x}",
               originDie.GetDie()->section_offset);
        return false;
      }
      dieRef = state.mReferedDie.value();
      state.mReferedDie.reset();
    }
  }
  auto variableTypeDie = obj.GetDebugInfoEntryReference(state.mTypeId->unsigned_value());
  ASSERT(variableTypeDie.has_value(), "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
         state.mTypeId->unsigned_value());

  auto type = process_type(variableTypeDie.value());
  if (state.mLocation->form == AttributeForm::DW_FORM_sec_offset) {
    processedSymbolStack.emplace_back(
      type, SymbolLocation::UnreadLocationList(static_cast<u32>(state.mLocation->unsigned_value())),
      state.mName->string());
  } else {
    DataBlock dwarf_expr_block = state.mLocation->block();
    std::span<const u8> expr{dwarf_expr_block.ptr, dwarf_expr_block.size};
    processedSymbolStack.emplace_back(type, SymbolLocation::Expression(expr), state.mName->string());
  }
  return true;
}

void
FunctionSymbolicationContext::ProcessVariable(DieReference dieRef) noexcept
{
  ProcessVariableDie(dieRef, lexicalBlockStack.back().mSymbols);
}

void
FunctionSymbolicationContext::ProcessFormalParameter(DieReference dieRef) noexcept
{
  ProcessVariableDie(dieRef, params.mSymbols);
}

void
FunctionSymbolicationContext::process_variable(DieReference cu_die) noexcept
{
  const auto location = cu_die.read_attribute(Attribute::DW_AT_location);
  const auto name = cu_die.read_attribute(Attribute::DW_AT_name);
  const auto type_id = cu_die.read_attribute(Attribute::DW_AT_type);

  ASSERT(location, "Expected to find location attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
         to_str(cu_die.GetDie()->tag));
  ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
         "loclistx location descriptors not supported yet. cu=0x{:x}, die=0x{:x}",
         cu_die.GetUnitData()->SectionOffset(), cu_die.GetDie()->section_offset);
  ASSERT(name, "Expected to find location attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
         to_str(cu_die.GetDie()->tag));
  ASSERT(type_id, "Expected to find location attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
         to_str(cu_die.GetDie()->tag));
  auto containing_cu_die_ref = obj.GetDebugInfoEntryReference(type_id->unsigned_value());
  ASSERT(containing_cu_die_ref.has_value(), "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
         type_id->unsigned_value());

  auto type = process_type(containing_cu_die_ref.value());
  DataBlock dwarf_expr_block = location->block();
  std::span<const u8> expr{dwarf_expr_block.ptr, dwarf_expr_block.size};
  lexicalBlockStack.back().mSymbols.emplace_back(type, SymbolLocation::Expression(expr), name->string());
}

void
FunctionSymbolicationContext::process_formal_param(DieReference cu_die) noexcept
{

  const auto location = cu_die.read_attribute(Attribute::DW_AT_location);
  const auto name = cu_die.read_attribute(Attribute::DW_AT_name);
  const auto type_id = cu_die.read_attribute(Attribute::DW_AT_type);

  ASSERT(location, "Expected to find location attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
         to_str(cu_die.GetDie()->tag));
  ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
         "loclistx location descriptors not supported yet. cu=0x{:x}, die=0x{:x}",
         cu_die.GetUnitData()->SectionOffset(), cu_die.GetDie()->section_offset);
  if (!name) {
    DBGLOG(core, "Expected to find name attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
           to_str(cu_die.GetDie()->tag));
    return;
  }
  ASSERT(type_id, "Expected to find type_id attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
         to_str(cu_die.GetDie()->tag));

  auto containing_cu_die_ref = obj.GetDebugInfoEntryReference(type_id->unsigned_value());
  ASSERT(containing_cu_die_ref.has_value(), "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
         type_id->unsigned_value());

  auto type = process_type(containing_cu_die_ref.value());
  DataBlock dwarf_expr_block = location->block();
  std::span<const u8> expr{dwarf_expr_block.ptr, dwarf_expr_block.size};
  params.mSymbols.emplace_back(type, SymbolLocation::Expression(expr), name->string());
}

void
FunctionSymbolicationContext::process_symbol_information() noexcept
{
  if (mFunctionSymbol->IsResolved()) {
    return;
  }

  for (const auto indexedDie : mFunctionSymbol->OriginDebugInfoEntries()) {
    auto cu = indexedDie.GetUnitData();
    auto die_index = indexedDie.GetIndex();
    auto cu_die_ref = cu->GetDieByCacheIndex(die_index);
    ASSERT(cu_die_ref.GetDie()->tag == DwarfTag::DW_TAG_subprogram,
           "Origin die for a fn wasn't subprogram! It was: {}", to_str(cu_die_ref.GetDie()->tag));

    auto die_it = cu_die_ref.GetDie()->children();
    // Means this fn ctx has no children. Whatever meta data (like pc start, pc end, etc) we may have, must already
    // have been processed.
    if (die_it == nullptr) {
      return;
    }
    const auto parent = cu_die_ref.GetDie();
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
        ProcessFormalParameter(DieReference{cu_die_ref.GetUnitData(), die_it});
        die_it = next(die_it, die_it->sibling());
      } break;
      case DwarfTag::DW_TAG_variable:
        ++frame_locals_count;
        ProcessVariable(DieReference{cu_die_ref.GetUnitData(), die_it});
        die_it = next(die_it, die_it->sibling());
        break;
      case DwarfTag::DW_TAG_lexical_block:
        process_lexical_block(DieReference{cu_die_ref.GetUnitData(), die_it});
        die_it = next(die_it, die_it->children());
        break;
      case DwarfTag::DW_TAG_inlined_subroutine:
        ProcessInlinedSubroutine(DieReference{cu_die_ref.GetUnitData(), die_it});
        die_it = next(die_it, die_it->sibling());
        break;
      default:
        DBGLOG(core, "[WARNING]: Unexpected Tag in subprorogram die: {}", to_str(die_it->tag));
        die_it = next(die_it, die_it->sibling());
        break;
      }
    }
  }
  std::swap(mFunctionSymbol->mFormalParametersBlock, params);
  std::swap(mFunctionSymbol->mFunctionSymbolBlocks, lexicalBlockStack);
  mFunctionSymbol->mFrameLocalVariableCount = frame_locals_count;
  mFunctionSymbol->mFullyParsed = true;
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

  auto containing_cu_die_ref = obj.GetDebugInfoEntryReference(type_id->unsigned_value());
  auto type = obj.GetTypeStorage()->GetOrCreateNewType(containing_cu_die_ref->AsIndexed());
  auto ctx = TypeSymbolicationContext::continueWith(*this, type);
  ctx.resolve_type();

  if (!type->mFields.empty()) {
    const auto member_offset = location->unsigned_value();
    for (auto t : type->mFields) {
      type_fields.push_back(Field{.type = t.type, .offset_of = *t.offset_of + member_offset, .name = t.name});
    }
  }
}

static std::string_view
name_from_tag(DwarfTag tag) noexcept
{
  switch (tag) {
  case DwarfTag::DW_TAG_class_type:
    return "class";
  case DwarfTag::DW_TAG_enumeration_type:
    return "enum";
  case DwarfTag::DW_TAG_structure_type:
    return "structure";
  case DwarfTag::DW_TAG_union_type:
    return "union";
  default:
    break;
  }
  ASSERT(false, "Did not expect that DwarfTag");
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
           cu_die.GetDie()->section_offset,
           name.transform([](auto v) { return v.string(); }).value_or("die had no name"));
    return;
  }

  ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
         "loclistx location descriptors not supported yet. cu=0x{:x}, die=0x{:x}",
         cu_die.GetUnitData()->SectionOffset(), cu_die.GetDie()->section_offset);
  ASSERT(type_id, "Expected to find type attribute for die 0x{:x} ({})", cu_die.GetDie()->section_offset,
         to_str(cu_die.GetDie()->tag));

  if (!name) {
    // means we're likely some anonymous structure of some kind
    auto containing_cu_die_ref = obj.GetDebugInfoEntryReference(type_id->unsigned_value());
    ASSERT(containing_cu_die_ref.has_value(),
           "Failed to get compilation unit & die reference from DIE offset: 0x{:x}", type_id->unsigned_value());
    auto type = obj.GetTypeStorage()->GetOrCreateNewType(containing_cu_die_ref->AsIndexed());
    const auto member_offset = location->unsigned_value();
    auto name = name_from_tag(type->mDebugInfoEntryTag);
    this->type_fields.push_back(Field{.type = NonNull(*type), .offset_of = member_offset, .name = name});
  } else {
    auto containing_cu_die_ref = obj.GetDebugInfoEntryReference(type_id->unsigned_value());
    ASSERT(containing_cu_die_ref.has_value(),
           "Failed to get compilation unit & die reference from DIE offset: 0x{:x}", type_id->unsigned_value());
    auto type = obj.GetTypeStorage()->GetOrCreateNewType(containing_cu_die_ref->AsIndexed());
    const auto member_offset = location->unsigned_value();
    this->type_fields.push_back(Field{.type = NonNull(*type), .offset_of = member_offset, .name = name->string()});
  }
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
    if (type_iter->mIsResolved) {
      type_iter = type_iter->mTypeChain;
      continue;
    }
    auto cu = type_iter->mCompUnitDieReference->GetUnitData();
    auto die = type_iter->mCompUnitDieReference.mut().GetDie();
    auto typedie = DieReference{cu, die};
    if (die->tag == DwarfTag::DW_TAG_enumeration_type) {
      const auto type_id = typedie.read_attribute(Attribute::DW_AT_type);
      if (type_id) {
        auto containing_cu_die_ref = obj.GetDebugInfoEntryReference(type_id->unsigned_value());
        enumeration_type = obj.GetTypeStorage()->GetOrCreateNewType(containing_cu_die_ref->AsIndexed());
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

    if (typedie.GetDie()->tag == DwarfTag::DW_TAG_enumeration_type) {
      type_iter->mEnumValues = {.is_signed = enum_is_signed,
                                .e_values = std::make_unique<EnumeratorConstValue[]>(type_fields.size())};
      std::copy(const_values.begin(), const_values.end(), type_iter->mEnumValues.e_values.get());
    }

    if (!type_fields.empty()) {
      std::swap(type_iter->mFields, this->type_fields);
    }
    type_iter->mIsResolved = true;
    type_iter = type_iter->mTypeChain;
  }
}

} // namespace sym::dw