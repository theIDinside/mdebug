/** LICENSE TEMPLATE */
#include "typeread.h"
#include "lib/static_vector.h"
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
      mParams{ .mRanges = { AddressRange{ .low = mFunctionSymbol->StartPc(), .high = mFunctionSymbol->EndPc() } },
        .mSymbols = {} }
{
  mLexicalBlockStack.emplace_back(
    std::vector{ AddressRange{ .low = mFunctionSymbol->StartPc(), .high = mFunctionSymbol->EndPc() } },
    std::vector<Symbol>{});
  MDB_ASSERT(mLexicalBlockStack.size() == 1, "Expected block stack size == 1, was {}", mLexicalBlockStack.size());
  MUST_HOLD(mFunctionSymbol != nullptr,
    "To parse symbol information for a function, there must exist symbol information to parse.");
}

NonNullPtr<Type>
FunctionSymbolicationContext::ProcessTypeDie(DieReference dieRef) noexcept
{
  sym::Type *t = mObjectRef.GetTypeStorage()->GetOrCreateNewType(dieRef.AsIndexed());
  if (t == nullptr) {
    PANIC("Failed to get or prepare new type to be realized");
  }
  if (dieRef.TypeDieIsDeclaration()) {
    t->SetIsDeclaration();
  }
  return NonNull(*t);
}

void
FunctionSymbolicationContext::ProcessLexicalBlockDie(DieReference die) noexcept
{
  AddrPtr low = nullptr;
  AddrPtr hi = nullptr;
  const auto block_seen = [&]() { return low != nullptr && hi != nullptr; };
  const auto &attr = die.GetUnitData()->GetAbbreviation(die.GetDie()->mAbbreviationCode);
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
  std::optional<DieReference> mReferedDie{ std::nullopt };
  DieAttributeRead mProceed{ DieAttributeRead::Skipped };

  [[nodiscard]] constexpr bool
  ParsedEnough() const noexcept
  {
    return (mLocation && mName && mTypeId);
  }

  static DieAttributeRead
  Proceed()
  {
    return DieAttributeRead::Continue;
  }
};

bool
FunctionSymbolicationContext::ProcessVariableDie(
  DieReference variableDebugInfoEntry, std::vector<Symbol> &processedSymbolStack) noexcept
{
  ParseState state;
  const DieReference originDie = variableDebugInfoEntry;
  for (;;) {
    sym::dw::ProcessDie(variableDebugInfoEntry,
      [&state, this](UnitReader &reader, Abbreviation &abbreviation, const AbbreviationInfo &info) {
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
          state.mReferedDie = mObjectRef.GetDebugInfoEntryReference(declaring_die_offset);
          return DieAttributeRead::Continue;
        }
        default:
          return DieAttributeRead::Skipped;
        }
      });
    if (state.ParsedEnough()) {
      break;
    }
    if (!state.mReferedDie) {
      DBGLOG(dwarf,
        "[ProcessVariableDie]: Ignoring DW_TAG_variable die, incomplete symbol information. die=0x{:x}",
        originDie.GetDie()->mSectionOffset);
      return false;
    }
    variableDebugInfoEntry = state.mReferedDie.value();
    state.mReferedDie.reset();
  }
  std::optional<DieReference> variableTypeDie =
    mObjectRef.GetDebugInfoEntryReference(state.mTypeId->AsUnsignedValue());
  MDB_ASSERT(variableTypeDie.has_value(),
    "Failed to get compilation unit die reference from DIE offset: 0x{:x}",
    state.mTypeId->AsUnsignedValue());

  NonNullPtr<sym::Type> type = ProcessTypeDie(variableTypeDie.value());
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
    UnitData *cu = indexedDie.GetUnitData();
    auto dieIndex = indexedDie.GetIndex();
    auto compUnitDieReference = cu->GetDieByCacheIndex(dieIndex);
    MDB_ASSERT(compUnitDieReference.GetDie()->mTag == DwarfTag::DW_TAG_subprogram,
      "Origin die for a fn wasn't subprogram! It was: {}",
      to_str(compUnitDieReference.GetDie()->mTag));

    const DieMetaData *dieIterator = compUnitDieReference.GetDie()->GetChildren();
    // Means this fn ctx has no children. Whatever meta data (like pc start, pc end, etc) we may have, must already
    // have been processed.
    if (dieIterator == nullptr) {
      return;
    }
    const DieMetaData *parent = compUnitDieReference.GetDie();
    const auto next = [&parent](auto curr, auto next) {
      if (next) {
        return next;
      }
      auto test = curr->GetParent();
      while (!test->Sibling() && test != parent) {
        test = test->GetParent();
      }
      return (test == parent) ? parent : test->Sibling();
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
    : mObjectRef(object_file), mRequestedTypeDieToResolve(&type)
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
  sym::Type *type = mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());
  TypeSymbolicationContext ctx = TypeSymbolicationContext::ContinueWith(*this, type);
  ctx.ResolveType();

  if (!type->mFields.empty()) {
    const auto member_offset = location->AsUnsignedValue();
    for (auto t : type->mFields) {
      mTypeFields.push_back(Field{ .mType = t.mType,
        .mObjectBaseOffset = *t.mObjectBaseOffset + member_offset,
        .mFieldOffset = 0,
        .mBitFieldSize = 0,
        .mName = t.mName });
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
TypeDIEContext::Reserve(size_t size)
{
  mAncestorDies.reserve(size);
}

TypeDIEContext::TypeDIEContext(DwarfTag tag) : mTag(tag) {}

void
TypeDIEContext::AppendDie(DieReference dieRef)
{
  mAncestorDies.emplace_back(dieRef.GetDie()->mTag, dieRef);
}

static bool
IsDWARFUnit(DwarfTag tag)
{
  using enum DwarfTag;
  switch (tag) {
  case DW_TAG_compile_unit:
    [[fallthrough]];
  case DW_TAG_partial_unit:
    [[fallthrough]];
  case DW_TAG_type_unit:
    [[fallthrough]];
  case DW_TAG_skeleton_unit:
    return true;
  default:
    return false;
  }
}

/* static */
TypeDIEContext
TypeDIEContext::Create(DieReference dieRef)
{
  TypeDIEContext result{ dieRef.GetDie()->mTag };

  result.AppendDie(dieRef);
  for (auto ref = dieRef.GetParent(); ref.has_value(); ref = ref->GetParent()) {
    // We use DWARFDIEContext to compare two (or more) chains of DIE's. They will belong to different files
    // so adding those, makes absolutely no sense at all.
    if (IsDWARFUnit(ref->GetDie()->mTag)) {
      return result;
    }
    result.AppendDie(*ref);
  }

  return result;
}

bool
TypeDIEContext::TypeContextMatches(const TypeDIEContext &other) const
{
  return *this == other;
}

bool
TypeDIEContext::operator==(const TypeDIEContext &rhs) const
{
  if (mAncestorDies.size() != rhs.mAncestorDies.size()) {
    DBGLOG(core,
      "dies had different amount of ancestors, left={}, right={}",
      mAncestorDies.size(),
      rhs.mAncestorDies.size());
    return false;
  }

  const bool matchingTags = std::ranges::equal(
    mAncestorDies, rhs.mAncestorDies, [](const DieContextEntry &lhs, const DieContextEntry &rhs) {
      if (lhs.mTag == rhs.mTag) {
        return true;
      }

      // gcc apparently can have these be interchangeable.
      return (lhs.mTag == DwarfTag::DW_TAG_structure_type && rhs.mTag == DwarfTag::DW_TAG_class_type) ||
             (rhs.mTag == DwarfTag::DW_TAG_structure_type && lhs.mTag == DwarfTag::DW_TAG_class_type);
    });

  if (!matchingTags) {
    DBGLOG(core, "dies had different tags");
    return false;
  }

  return std::ranges::equal(
    mAncestorDies, rhs.mAncestorDies, [](const DieContextEntry &lhs, const DieContextEntry &rhs) {
      const auto leftName = lhs.mDie.ReadAttribute(Attribute::DW_AT_name).transform(AttributeValue::ToStringView);
      const auto rightName = rhs.mDie.ReadAttribute(Attribute::DW_AT_name).transform(AttributeValue::ToStringView);
      if (leftName && rightName) {
        DBGBUFLOG(core, "leftDie={}, rightDie={}", *leftName, *rightName);
      }
      return leftName == rightName;
    });
}

void
TypeSymbolicationContext::ProcessMemberVariable(DieReference cu_die) noexcept
{
  const auto locAttribute = cu_die.ReadAttribute(Attribute::DW_AT_data_member_location);
  auto location = locAttribute.transform(AttributeValue::AsUnsigned);

  const auto name = cu_die.ReadAttribute(Attribute::DW_AT_name);
  const auto typeId = cu_die.ReadAttribute(Attribute::DW_AT_type);

  u32 byteOffset = 0;
  u32 bitFieldOffset = 0;
  u16 bitFieldSize = 0;

  // A member without a location is not a member. It can be a static variable or a constexpr variable.
  if (!location) {
    const auto bitSize = cu_die.ReadAttribute(Attribute::DW_AT_bit_size).transform(AttributeValue::AsUnsigned);
    if (!bitSize) {
      DBGLOG(core,
        "cu={}, die 0x{:x} (name={}) is DW_TAG_member but had no location or bit_size",
        cu_die.GetUnitData()->SectionOffset(),
        cu_die.GetDie()->mSectionOffset,
        name.transform([](const auto &v) { return v.AsCString(); }).value_or("die had no name"));
      return;
    }
    const auto dataBitOffset =
      cu_die.ReadAttribute(Attribute::DW_AT_data_bit_offset).transform(AttributeValue::AsUnsigned);
    location = std::make_optional(*dataBitOffset / 8);
    bitFieldOffset = *dataBitOffset % 8;
    bitFieldSize = *bitSize;
  }

  MDB_ASSERT(locAttribute->form != AttributeForm::DW_FORM_loclistx,
    "loclistx location descriptors not supported yet. cu={}, die=0x{:x}",
    cu_die.GetUnitData()->SectionOffset(),
    cu_die.GetDie()->mSectionOffset);
  MDB_ASSERT(typeId,
    "Expected to find type attribute for die 0x{:x} ({})",
    cu_die.GetDie()->mSectionOffset,
    to_str(cu_die.GetDie()->mTag));

  byteOffset = (*location);

  if (!name) {
    // means we're likely some anonymous structure of some kind
    auto containingCompUnitDieReference = mObjectRef.GetDebugInfoEntryReference(typeId->AsUnsignedValue());
    MDB_ASSERT(containingCompUnitDieReference.has_value(),
      "Failed to get compilation unit & die reference from DIE offset: 0x{:x}",
      typeId->AsUnsignedValue());
    sym::Type *type = mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());
    auto name = name_from_tag(type->mDebugInfoEntryTag);
    this->mTypeFields.push_back(Field{ .mType = NonNull(*type),
      .mObjectBaseOffset = byteOffset,
      .mFieldOffset = bitFieldOffset,
      .mBitFieldSize = bitFieldSize,
      .mName = name });
  } else {
    auto containingCompUnitDieReference = mObjectRef.GetDebugInfoEntryReference(typeId->AsUnsignedValue());
    MDB_ASSERT(containingCompUnitDieReference.has_value(),
      "Failed to get compilation unit & die reference from DIE offset: 0x{:x}",
      typeId->AsUnsignedValue());
    sym::Type *type = mObjectRef.GetTypeStorage()->GetOrCreateNewType(containingCompUnitDieReference->AsIndexed());

    this->mTypeFields.push_back(Field{ .mType = NonNull(*type),
      .mObjectBaseOffset = byteOffset,
      .mFieldOffset = bitFieldOffset,
      .mBitFieldSize = bitFieldSize,
      .mName = name->AsCString() });
  }
}

void
TypeSymbolicationContext::ProcessEnumDie(DieReference compUnitDie) noexcept
{
  const auto name = compUnitDie.ReadAttribute(Attribute::DW_AT_name);
  const auto memberOffset = compUnitDie.ReadAttribute(Attribute::DW_AT_data_member_location)
                              .transform([](const auto &v) { return v.AsUnsignedValue(); })
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

  this->mTypeFields.push_back(Field{ .mType = NonNull(*mEnumerationType),
    .mObjectBaseOffset = memberOffset,
    .mFieldOffset = 0,
    .mBitFieldSize = 0,
    .mName = name->AsCString() });
}

void
TypeSymbolicationContext::ResolveDeclarationType(sym::Type *type)
{
  auto *cu = type->mCompUnitDieReference->GetUnitData();
  DieReference leafDie = type->mCompUnitDieReference->ToDieReference();
  const auto declarationDieContext = TypeDIEContext::Create(leafDie);

  // Thankfully a declaration will have the _exact_ name required making us able to skip the regex-search of debug
  // string ELF section. I hope to god it does, at least. Or, one could resolve to linkage name here to be
  // *exactly* sure that we resolve this. Probably better?
  mObjectRef.ForEachStructOrClassType(
    type->mName, true, [type, &declarationDieContext, this](sym::Type *candidateType) {
      if (candidateType == type) {
        return true;
      }

      const auto candidateDieRef = candidateType->mCompUnitDieReference->ToDieReference();
      const TypeDIEContext definitionDieContext = TypeDIEContext::Create(candidateDieRef);

      if (declarationDieContext.TypeContextMatches(definitionDieContext)) {
        mObjectRef.GetTypeStorage()->AddType(candidateDieRef.SectionOffset(), candidateType);
        type->mTypeChain = candidateType;
        return false;
      }

      return true;
    });
}

void
TypeSymbolicationContext::ResolveType() noexcept
{
  sym::Type *typeIter = mRequestedTypeDieToResolve;
  while (typeIter != nullptr) {
    if (typeIter->mIsResolved) {
      typeIter = typeIter->mTypeChain;
      continue;
    }
    if (typeIter->mIsDeclaration) {
      ResolveDeclarationType(typeIter);
      // At this point, the declaration die, shall have the actual defined type in it's type chain.
      // We shall also, have overwritten the declaration die in the type storage, so anybody referencing a Type*
      // via that offset, will now actually get the defined Type* directly. However, any type accessing Type* via
      // the type chain, will have to iterate past the declaration type in the type chain, as we can't fixup these.
      // This is fine for now, but not optimal, it's an additional check needed when doing operations requiring
      // types. Note that I have no idea on how to implement this better atm because I've spent on it.

      if (!typeIter->mTypeChain) {
        DBGLOG(core,
          "Found no definition die for declaration die 0x{:x}, setting as resolved still.",
          typeIter->mCompUnitDieReference->ToDieReference().GetDie()->mSectionOffset);
        typeIter->mIsResolved = true;
        return;
      }

      typeIter->mIsResolved = true;

      typeIter = mRequestedTypeDieToResolve = typeIter->mTypeChain;
      if (typeIter->IsResolved()) {
        // Definition type die has already been parsed.
        return;
      }
      // Now resolve the actual definition die
    }
    UnitData *cu = typeIter->mCompUnitDieReference->GetUnitData();
    const DieMetaData *die = typeIter->mCompUnitDieReference.mut().GetDie();
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