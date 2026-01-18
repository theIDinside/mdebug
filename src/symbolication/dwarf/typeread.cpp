/** LICENSE TEMPLATE */
#include "typeread.h"
#include "symbolication/block.h"
#include "symbolication/dwarf/attribute_read.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf/die_iterator.h"
#include "symbolication/dwarf_attribute_value.h"
#include "symbolication/dwarf_defs.h"
#include "symbolication/type.h"
#include "utils/logger.h"
#include <symbolication/callstack.h>
#include <symbolication/objfile.h>

namespace mdb::sym::dw {

FunctionSymbolicationContext::FunctionSymbolicationContext(ObjectFile &obj, sym::Frame &frame) noexcept
    : mObjectRef(obj), mFunctionSymbol(frame.MaybeGetFullSymbolInfo()),
      mParams{ { AddressRange{ mFunctionSymbol->StartPc(), mFunctionSymbol->EndPc() } }, {} }, mLexicalBlockStack()
{
  mLexicalBlockStack.emplace_back(
    std::vector{ AddressRange{ mFunctionSymbol->StartPc(), mFunctionSymbol->EndPc() } }, std::vector<Symbol>{});
  MDB_ASSERT(mLexicalBlockStack.size() == 1, "Expected block stack size == 1, was {}", mLexicalBlockStack.size());
  MUST_HOLD(mFunctionSymbol != nullptr,
    "To parse symbol information for a function, there must exist symbol information to parse.");
}

NonNullPtr<Type>
FunctionSymbolicationContext::ProcessTypeDie(DieReference die) noexcept
{
  auto t = mObjectRef.GetTypeStorage()->GetOrCreateNewType(die.AsIndexed());
  if (t == nullptr) {
    PANIC("Failed to get or prepare new type to be realized");
  }
  return NonNull(*t);
}

void
FunctionSymbolicationContext::ProcessLexicalBlockDie(DieReference die) noexcept
{
  AddrPtr low = nullptr, hi = nullptr;
  const auto block_seen = [&]() { return low != nullptr && hi != nullptr; };
  auto &attr = die.GetUnitData()->GetAbbreviation(die.GetDie()->mAbbreviationCode);
  UnitReader reader{ die.GetUnitData() };
  reader.SeekDie(*die.GetDie());

  bool hadRanges = false;
  for (const auto &abbr : attr.mAttributes) {
    const auto value = ReadAttributeValue(reader, abbr, attr.mImplicitConsts);
    if (abbr.mName == Attribute::DW_AT_ranges) {
      hadRanges = true;
      auto ranges = mObjectRef.ReadDebugRanges(value.AsUnsignedValue());
      mLexicalBlockStack.emplace_back(std::move(ranges), std::vector<Symbol>{});
    }
    if (value.name == Attribute::DW_AT_low_pc || value.name == Attribute::DW_AT_entry_pc) {
      low = value.AsAddress();
    }
    if (value.name == Attribute::DW_AT_high_pc) {
      // high address is (low + offset) when IsDataForm
      if (value.IsDataForm()) {
        hi = low + value.AsUnsignedValue();
      } else {
        hi = value.AsAddress();
      }
    }
  }

  if (hadRanges) {
    MDB_ASSERT(low == nullptr, "We need to adjust the ranges by LOW PC I think.");
    return;
  }

  for (const auto abbr : attr.mAttributes) {
    auto value = ReadAttributeValue(reader, abbr, attr.mImplicitConsts);

    if (value.name == Attribute::DW_AT_high_pc) {
      hi = value.AsAddress();
    }
    if (block_seen()) {
      break;
    }
  }
  mLexicalBlockStack.emplace_back(std::vector{ AddressRange{ low, low + hi } }, std::vector<Symbol>{});
}

void
FunctionSymbolicationContext::ProcessInlinedSubroutineDie(DieReference cu_die) noexcept
{
  DBGLOG(core,
    "[symbolication]: process_inline not implemented (cu={}, die=0x{:x}), objfile={}",
    cu_die.GetUnitData()->SectionOffset(),
    cu_die.GetDie()->mSectionOffset,
    mObjectRef.GetObjectFileId());
}

struct ParseState
{
  using Data = std::optional<AttributeValue>;
  Data mLocation;
  Data mName;
  Data mTypeId;
  std::optional<DieReference> mReferedDie{};
  DieAttributeRead mProceed{ DieAttributeRead::Skipped };

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
FunctionSymbolicationContext::ProcessVariableDie(
  DieReference dieRef, std::vector<Symbol> &processedSymbolStack) noexcept
{
  ParseState state;
  const auto originDie = dieRef;
  for (;;) {
    sym::dw::ProcessDie(
      dieRef, [&state, &dieRef](UnitReader &reader, Abbreviation &abbreviation, const AbbreviationInfo &info) {
        switch (abbreviation.mName) {
        case Attribute::DW_AT_location:
          state.mLocation = ReadAttributeValue(reader, abbreviation, info.mImplicitConsts);
          return state.ParsedEnough() ? DieAttributeRead::Done : DieAttributeRead::Continue;
        case Attribute::DW_AT_name:
          state.mName = ReadAttributeValue(reader, abbreviation, info.mImplicitConsts);
          return state.ParsedEnough() ? DieAttributeRead::Done : DieAttributeRead::Continue;
        case Attribute::DW_AT_type:
          state.mTypeId = ReadAttributeValue(reader, abbreviation, info.mImplicitConsts);
          return state.ParsedEnough() ? DieAttributeRead::Done : DieAttributeRead::Continue;
        case Attribute::DW_AT_abstract_origin:
          [[fallthrough]];
        case Attribute::DW_AT_specification: {
          auto refereeValue = ReadAttributeValue(reader, abbreviation, info.mImplicitConsts);
          const auto declaring_die_offset = refereeValue.AsUnsignedValue();
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
          originDie.GetDie()->mSectionOffset);
        return false;
      }
      dieRef = state.mReferedDie.value();
      state.mReferedDie.reset();
    }
  }
  auto variableTypeDie = mObjectRef.GetDebugInfoEntryReference(state.mTypeId->AsUnsignedValue());
  MDB_ASSERT(variableTypeDie.has_value(),
    "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
    state.mTypeId->AsUnsignedValue());

  auto type = ProcessTypeDie(variableTypeDie.value());
  if (state.mLocation->form == AttributeForm::DW_FORM_sec_offset) {
    processedSymbolStack.emplace_back(type,
      SymbolLocation::UnreadLocationList(static_cast<u32>(state.mLocation->AsUnsignedValue())),
      state.mName->AsCString());
  } else {
    DataBlock dwarf_expr_block = state.mLocation->AsDataBlock();
    std::span<const u8> expr{ dwarf_expr_block.ptr, dwarf_expr_block.size };
    processedSymbolStack.emplace_back(type, SymbolLocation::Expression(expr), state.mName->AsCString());
  }
  return true;
}

void
FunctionSymbolicationContext::ProcessVariable(DieReference dieRef) noexcept
{
  ProcessVariableDie(dieRef, mLexicalBlockStack.back().mSymbols);
}

void
FunctionSymbolicationContext::ProcessFormalParameter(DieReference dieRef) noexcept
{
  ProcessVariableDie(dieRef, mParams.mSymbols);
}

void
FunctionSymbolicationContext::ProcessSymbolInformation() noexcept
{
  PROFILE_SCOPE_ARGS("FunctionSymbolicationContext::ProcessSymbolInformation",
    "symbolication",
    PEARG("function", this->mFunctionSymbol->name));
  if (mFunctionSymbol->IsResolved()) {
    return;
  }

  for (const auto indexedDie : mFunctionSymbol->OriginDebugInfoEntries()) {
    auto cu = indexedDie.GetUnitData();
    auto dieIndex = indexedDie.GetIndex();
    auto compUnitDieReference = cu->GetDieByCacheIndex(dieIndex);
    MDB_ASSERT(compUnitDieReference.GetDie()->mTag == DwarfTag::DW_TAG_subprogram,
      "Origin die for a fn wasn't subprogram! It was: {}",
      to_str(compUnitDieReference.GetDie()->mTag));

    auto dieIterator = compUnitDieReference.GetDie()->GetChildren();
    // Means this fn ctx has no children. Whatever meta data (like pc start, pc end, etc) we may have, must already
    // have been processed.
    if (dieIterator == nullptr) {
      return;
    }
    const auto parent = compUnitDieReference.GetDie();
    const auto next = [&parent](auto curr, auto next) {
      if (next) {
        return next;
      } else {
        auto test = curr->GetParent();
        while (!test->Sibling() && test != parent) {
          test = test->GetParent();
        }
        return (test == parent) ? parent : test->Sibling();
      }
    };

    while (dieIterator != parent) {
      switch (dieIterator->mTag) {
      case DwarfTag::DW_TAG_formal_parameter: {
        ProcessFormalParameter(DieReference{ compUnitDieReference.GetUnitData(), dieIterator });
        dieIterator = next(dieIterator, dieIterator->Sibling());
      } break;
      case DwarfTag::DW_TAG_variable:
        ++mFrameLocalsCount;
        ProcessVariable(DieReference{ compUnitDieReference.GetUnitData(), dieIterator });
        dieIterator = next(dieIterator, dieIterator->Sibling());
        break;
      case DwarfTag::DW_TAG_lexical_block:
        ProcessLexicalBlockDie(DieReference{ compUnitDieReference.GetUnitData(), dieIterator });
        dieIterator = next(dieIterator, dieIterator->GetChildren());
        break;
      case DwarfTag::DW_TAG_inlined_subroutine:
        ProcessInlinedSubroutineDie(DieReference{ compUnitDieReference.GetUnitData(), dieIterator });
        dieIterator = next(dieIterator, dieIterator->Sibling());
        break;
      default:
        DBGLOG(core, "[WARNING]: Unexpected Tag in subprorogram die: {}", to_str(dieIterator->mTag));
        dieIterator = next(dieIterator, dieIterator->Sibling());
        break;
      }
    }
  }
  std::swap(mFunctionSymbol->mFormalParametersBlock, mParams);
  std::swap(mFunctionSymbol->mFunctionSymbolBlocks, mLexicalBlockStack);
  mFunctionSymbol->mFrameLocalVariableCount = mFrameLocalsCount;
  mFunctionSymbol->mFullyParsed = true;
}

TypeSymbolicationContext::TypeSymbolicationContext(ObjectFile &object_file, Type &type) noexcept
    : mObjectRef(object_file), mCurrentType(&type)
{
}

TypeSymbolicationContext
TypeSymbolicationContext::ContinueWith(const TypeSymbolicationContext &ctx, Type *t) noexcept
{
  return TypeSymbolicationContext{ ctx.mObjectRef, *t };
}

// Fully resolves `Type`

void
TypeSymbolicationContext::ProcessInheritanceDie(DieReference cu_die) noexcept
{
  const auto location = cu_die.ReadAttribute(Attribute::DW_AT_data_member_location);
  const auto type_id = cu_die.ReadAttribute(Attribute::DW_AT_type);

  auto containingCompUnitDieReference = mObjectRef.GetDebugInfoEntryReference(type_id->AsUnsignedValue());
  auto type = mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());
  auto ctx = TypeSymbolicationContext::ContinueWith(*this, type);
  ctx.ResolveType();

  if (!type->mFields.empty()) {
    const auto member_offset = location->AsUnsignedValue();
    for (auto t : type->mFields) {
      mTypeFields.push_back(
        Field{ .mType = t.mType, .mObjectBaseOffset = *t.mObjectBaseOffset + member_offset, .mName = t.mName });
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
  MDB_ASSERT(false, "Did not expect that DwarfTag");
  return "no tag";
}

void
TypeSymbolicationContext::ProcessMemberVariable(DieReference cu_die) noexcept
{

  const auto location = cu_die.ReadAttribute(Attribute::DW_AT_data_member_location);
  const auto name = cu_die.ReadAttribute(Attribute::DW_AT_name);
  const auto typeId = cu_die.ReadAttribute(Attribute::DW_AT_type);

  // A member without a location is not a member. It can be a static variable or a constexpr variable.
  if (!location) {
    DBGLOG(core,
      "cu={}, die 0x{:x} (name={}) is DW_TAG_member but had no location",
      cu_die.GetUnitData()->SectionOffset(),
      cu_die.GetDie()->mSectionOffset,
      name.transform([](auto v) { return v.AsCString(); }).value_or("die had no name"));
    return;
  }

  MDB_ASSERT(location->form != AttributeForm::DW_FORM_loclistx,
    "loclistx location descriptors not supported yet. cu={}, die=0x{:x}",
    cu_die.GetUnitData()->SectionOffset(),
    cu_die.GetDie()->mSectionOffset);
  MDB_ASSERT(typeId,
    "Expected to find type attribute for die 0x{:x} ({})",
    cu_die.GetDie()->mSectionOffset,
    to_str(cu_die.GetDie()->mTag));

  if (!name) {
    // means we're likely some anonymous structure of some kind
    auto containingCompUnitDieReference = mObjectRef.GetDebugInfoEntryReference(typeId->AsUnsignedValue());
    MDB_ASSERT(containingCompUnitDieReference.has_value(),
      "Failed to get compilation unit & die reference from DIE offset: 0x{:x}",
      typeId->AsUnsignedValue());
    auto type = mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());
    const auto member_offset = location->AsUnsignedValue();
    auto name = name_from_tag(type->mDebugInfoEntryTag);
    this->mTypeFields.push_back(
      Field{ .mType = NonNull(*type), .mObjectBaseOffset = member_offset, .mName = name });
  } else {
    auto containingCompUnitDieReference = mObjectRef.GetDebugInfoEntryReference(typeId->AsUnsignedValue());
    MDB_ASSERT(containingCompUnitDieReference.has_value(),
      "Failed to get compilation unit & die reference from DIE offset: 0x{:x}",
      typeId->AsUnsignedValue());
    auto type = mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());
    const auto member_offset = location->AsUnsignedValue();
    this->mTypeFields.push_back(
      Field{ .mType = NonNull(*type), .mObjectBaseOffset = member_offset, .mName = name->AsCString() });
  }
}

void
TypeSymbolicationContext::ProcessEnumDie(DieReference compUnitDie) noexcept
{
  const auto name = compUnitDie.ReadAttribute(Attribute::DW_AT_name);
  const auto memberOffset = compUnitDie.ReadAttribute(Attribute::DW_AT_data_member_location)
                              .transform([](auto v) { return v.AsUnsignedValue(); })
                              .value_or(0);
  const auto const_value = compUnitDie.ReadAttribute(Attribute::DW_AT_const_value);
  if (const_value) {
    mEnumIsSigned = const_value->form == AttributeForm::DW_FORM_sdata;
    if (mEnumIsSigned) {
      mConstValues.push_back(EnumeratorConstValue{ .i = const_value->AsSignedValue() });
    } else {
      mConstValues.push_back(EnumeratorConstValue{ .u = const_value->AsUnsignedValue() });
    }
  }

  this->mTypeFields.push_back(
    Field{ .mType = NonNull(*mEnumerationType), .mObjectBaseOffset = memberOffset, .mName = name->AsCString() });
}

void
TypeSymbolicationContext::ResolveType() noexcept
{
  auto typeIter = mCurrentType;
  while (typeIter != nullptr) {
    if (typeIter->mIsResolved) {
      typeIter = typeIter->mTypeChain;
      continue;
    }
    auto cu = typeIter->mCompUnitDieReference->GetUnitData();
    auto die = typeIter->mCompUnitDieReference.mut().GetDie();
    auto typedie = DieReference{ cu, die };
    if (die->mTag == DwarfTag::DW_TAG_enumeration_type) {
      const auto type_id = typedie.ReadAttribute(Attribute::DW_AT_type);
      if (type_id) {
        auto containingCompUnitDieReference = mObjectRef.GetDebugInfoEntryReference(type_id->AsUnsignedValue());
        mEnumerationType =
          mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());
      }
    }

    die = die->GetChildren();
    for (const auto die : sym::dw::IterateSiblings{ cu, die }) {
      switch (die.mTag) {
      case DwarfTag::DW_TAG_member:
        ProcessMemberVariable(DieReference{ cu, &die });
        break;
      case DwarfTag::DW_TAG_inheritance:
        ProcessInheritanceDie(DieReference{ cu, &die });
        break;
      case DwarfTag::DW_TAG_enumerator:
        ProcessEnumDie(DieReference{ cu, &die });
        break;
      default:
        continue;
      }
    }

    if (typedie.GetDie()->mTag == DwarfTag::DW_TAG_enumeration_type) {
      typeIter->mEnumValues = { .mIsSigned = mEnumIsSigned,
        .mEnumeratorValues = std::make_unique<EnumeratorConstValue[]>(mTypeFields.size()) };
      std::copy(mConstValues.begin(), mConstValues.end(), typeIter->mEnumValues.mEnumeratorValues.get());
    }

    if (!mTypeFields.empty()) {
      std::swap(typeIter->mFields, this->mTypeFields);
    }
    typeIter->mIsResolved = true;
    typeIter = typeIter->mTypeChain;
  }
}

} // namespace mdb::sym::dw