/** LICENSE TEMPLATE */
#include "type.h"

// mdb
#include <symbolication/dwarf/attribute_read.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/dwarf/die_iterator.h>
#include <symbolication/dwarf_attribute_value.h>
#include <symbolication/dwarf_defs.h>
#include <symbolication/objfile.h>

// std
#include <algorithm>
#include <optional>
#include <utility>

namespace mdb {
static constexpr bool
TypeHasQualifierOrIsReferenceLike(const sym::dw::DieMetaData *die)
{
  switch (die->mTag) {
  case DwarfTag::DW_TAG_pointer_type:
  case DwarfTag::DW_TAG_reference_type:
  case DwarfTag::DW_TAG_const_type:
  case DwarfTag::DW_TAG_volatile_type:
  case DwarfTag::DW_TAG_rvalue_reference_type:
  case DwarfTag::DW_TAG_array_type:
  case DwarfTag::DW_TAG_typedef:
    return true;
  default:
    return false;
  }
}

bool
sym::IsReferenceLike(const dw::DieMetaData *die) noexcept
{
  return IsReferenceLike(ToTypeModifierWillPanic(die->mTag));
}

bool
sym::IsReferenceLike(sym::Modifier modifier) noexcept
{
  switch (modifier) {
  case Modifier::Pointer:
  case Modifier::Reference:
  case Modifier::RValueReference:
  case Modifier::Array:
    return true;
  case Modifier::None:
  case Modifier::Atomic:
  case Modifier::Const:
  case Modifier::Immutable:
  case Modifier::Packed:
  case Modifier::Restrict:
  case Modifier::Shared:
  case Modifier::Volatile:
    return false;
  }
  NEVER("Unknown modifier");
}

sym::Modifier
sym::ToTypeModifierWillPanic(DwarfTag tag) noexcept
{
  switch (tag) {
  case DwarfTag::DW_TAG_array_type:
    return sym::Modifier::Array;
  case DwarfTag::DW_TAG_atomic_type:
    return sym::Modifier::Atomic;
  case DwarfTag::DW_TAG_const_type:
    return sym::Modifier::Const;
  case DwarfTag::DW_TAG_immutable_type:
    return sym::Modifier::Immutable;
  case DwarfTag::DW_TAG_packed_type:
    return sym::Modifier::Packed;
  case DwarfTag::DW_TAG_pointer_type:
    return sym::Modifier::Pointer;
  case DwarfTag::DW_TAG_reference_type:
    return sym::Modifier::Reference;
  case DwarfTag::DW_TAG_restrict_type:
    return sym::Modifier::Restrict;
  case DwarfTag::DW_TAG_rvalue_reference_type:
    return sym::Modifier::RValueReference;
  case DwarfTag::DW_TAG_shared_type:
    return sym::Modifier::Shared;
  case DwarfTag::DW_TAG_volatile_type:
    return sym::Modifier::Volatile;
  case DwarfTag::DW_TAG_base_type:
  case DwarfTag::DW_TAG_class_type:
  case DwarfTag::DW_TAG_structure_type:
  case DwarfTag::DW_TAG_enumeration_type:
  case DwarfTag::DW_TAG_union_type:
  case DwarfTag::DW_TAG_typedef:
  case DwarfTag::DW_TAG_subroutine_type:
  case DwarfTag::DW_TAG_unspecified_type:
    return sym::Modifier::None;
  default:
    break;
  }
  PANIC(std::format("DwarfTag not convertable to Type::Modifier: {}", to_str(tag)));
}

/* static */
std::unique_ptr<TypeStorage>
TypeStorage::Create() noexcept
{
  auto storage = std::make_unique<TypeStorage>();
  // TODO(simon): Technically there exists a world where a pointer is 4 bytes. I don't live in that world.
  storage->mTypeStorage[0] = new sym::Type{ "void", 8 };
  return storage;
}

TypeStorage::~TypeStorage() noexcept
{
  for (const auto [k, ptr] : mTypeStorage) {
    delete ptr;
  }
}

static constexpr auto REFERENCE_SIZE = 8u;

sym::Type *
TypeStorage::GetUnitType() noexcept
{
  return mTypeStorage[0];
}

static u32
ResolveArrayBounds(sym::dw::DieReference array_die) noexcept
{
  MDB_ASSERT(array_die.GetDie()->mHasChildren, "expected die {} to have children", array_die);

  for (const auto child : sym::dw::IterateSiblings{ array_die.GetUnitData(), array_die.GetDie()->GetChildren() }) {
    if (child.mTag == DwarfTag::DW_TAG_subrange_type) {
      const sym::dw::DieReference ref{ array_die.GetUnitData(), &child };
      u64 count{};
      sym::dw::ProcessDie(ref, [&](sym::dw::UnitReader &reader, sym::dw::Abbreviation &attr, const auto &info) {
        switch (attr.mName) {
        case Attribute::DW_AT_upper_bound:
          [[fallthrough]];
        case Attribute::DW_AT_count:
          count = sym::dw::ReadAttributeValue(reader, attr, info.mImplicitConsts).AsSignedValue() +
                  1u * std::clamp(u32(attr.mName == Attribute::DW_AT_upper_bound), 0u, 1u);
          return sym::dw::DieAttributeRead::Done;
        default:
          return sym::dw::DieAttributeRead::Continue;
        }
      });
      return count;
    }
  }
  return 0;
}

void
TypeStorage::AddType(u64 sectionOffset, sym::Type *type)
{
  mTypeStorage[sectionOffset] = type;
}

sym::Type *
TypeStorage::CreateTypeFromQualifiedTypeDie(sym::dw::DieReference dieRef)
{
  using DieReference = sym::dw::DieReference;

  const auto attr = dieRef.ReadAttribute(Attribute::DW_AT_type);
  sym::Type *baseType =
    attr.transform(AttributeValue::AsUnsigned)
      .and_then(
        [&](auto offset) { return dieRef.GetUnitData()->GetObjectFile()->GetDebugInfoEntryReference(offset); })
      .transform([this](DieReference referencedDie) { return GetOrCreateNewType(referencedDie.AsIndexed()); })
      .or_else([this]() -> std::optional<sym::Type *> { return GetUnitType(); })
      .value();
  auto size = 0U;
  auto arrayBounds = 0U;
  // TODO(simon): We only support 64-bit machines right now. Therefore all non-value types/reference-like types
  // are 8 bytes large
  if (sym::IsReferenceLike(dieRef.GetDie()) || baseType->IsReference()) {
    if (dieRef.GetDie()->mTag == DwarfTag::DW_TAG_array_type) {
      arrayBounds = ResolveArrayBounds(dieRef);
    }
    size = REFERENCE_SIZE;
  } else {
    size = baseType->Size();
  }

  auto *type = new sym::Type{
    dieRef.GetDie()->mTag, dieRef.AsIndexed(), size, baseType, dieRef.GetDie()->mTag == DwarfTag::DW_TAG_typedef
  };
  type->SetArrayBounds(arrayBounds);
  AddType(dieRef.GetDie()->mSectionOffset, type);
  return type;
}

sym::Type *
TypeStorage::CreateTypeFromDeclarationDie(sym::dw::DieReference dieRef)
{
  const u64 size =
    dieRef.ReadAttribute(Attribute::DW_AT_byte_size).transform(&AttributeValue::AsUnsigned).value_or(0);

  const auto name = dieRef.ReadAttribute(Attribute::DW_AT_name).transform(AttributeValue::ToStringView);

  if (!name.has_value()) {
    DBGLOG(core, "declaration die 0x{:x} had no name attribute", dieRef.GetDie()->mSectionOffset);
    return nullptr;
  }

  auto *type = new sym::Type{ dieRef.GetDie()->mTag, dieRef.AsIndexed(), static_cast<u32>(size), *name };
  type->SetIsDeclaration();
  AddType(dieRef.GetDie()->mSectionOffset, type);
  return type;
}

sym::Type *
TypeStorage::CreateTypeFromTypeSignatureDie(sym::dw::DieReference dieRef, u64 typeSignature)
{
  // DWARF5 support; we might run into type units, therefore we have to resolve the *actual* die we want here
  // yet we still want to map this_ref's die offset to the type. This is unfortunate, since we might get
  // "copies" i.e. mulitple die's that have a ref signature. The actual backing data is just 1 of though, so it
  // just means mulitple keys can reach the value, which is a pointer to the actual type.
  sym::dw::DieReference typeUnitDieRef =
    dieRef.GetUnitData()->GetObjectFile()->GetTypeUnitTypeDebugInfoEntry(typeSignature);
  MDB_ASSERT(typeUnitDieRef.IsValid(), "expected die reference to type unit to be valid");
  const u32 sz = typeUnitDieRef.ReadAttribute(Attribute::DW_AT_byte_size)->AsUnsignedValue();
  const auto name = typeUnitDieRef.ReadAttribute(Attribute::DW_AT_name)
                      .transform(AttributeValue::ToStringView)
                      .value_or("<no name>");
  auto *type = new sym::Type{ dieRef.GetDie()->mTag, typeUnitDieRef.AsIndexed(), sz, name };
  AddType(dieRef.GetDie()->mSectionOffset, type);
  return type;
}

sym::Type *
TypeStorage::CreateTypeFallback(sym::dw::DieReference dieRef)
{
  // lambdas have no assigned type name in DWARF (C++). That's just nutter butter shit.
  // Like come on dog. Give it a bogus name, whatever really. But nothing?
  const auto name = dieRef.ReadAttribute(Attribute::DW_AT_name)
                      .transform([](const auto &v) { return v.AsStringView(); })
                      .value_or("lambda");
  const u32 sz =
    dieRef.ReadAttribute(Attribute::DW_AT_byte_size).transform(AttributeValue::AsUnsigned).value_or(0);
  auto *type = new sym::Type{ dieRef.GetDie()->mTag, dieRef.AsIndexed(), sz, name };
  AddType(dieRef.GetDie()->mSectionOffset, type);
  return type;
}

sym::Type *
TypeStorage::GetOrCreateNewType(sym::dw::IndexedDieReference indexedDieRef) noexcept
{
  const sym::dw::DieReference dieRef{ indexedDieRef.GetUnitData(), indexedDieRef.GetDie() };
  const auto typeId = dieRef.GetDie()->mSectionOffset;

  if (mTypeStorage.contains(typeId)) {
    auto *t = mTypeStorage[typeId];
    return t;
  }

  if (TypeHasQualifierOrIsReferenceLike(dieRef.GetDie())) {
    return CreateTypeFromQualifiedTypeDie(dieRef);
  }

  // *maybe* an opaque type, but most likely just a forward declaration (or something like it.)
  if (dieRef.TypeDieIsDeclaration()) {
    return CreateTypeFromDeclarationDie(dieRef);
  }

  if (const auto &attributeValue = dieRef.ReadAttribute(Attribute::DW_AT_signature); attributeValue) {
    return CreateTypeFromTypeSignatureDie(dieRef, attributeValue->AsUnsignedValue());
  }
  return CreateTypeFallback(dieRef);
}

sym::Type *
TypeStorage::CreateNewType(DwarfTag tag,
  Offset typeDieOffset,
  sym::dw::IndexedDieReference dieReference,
  u32 typeSize,
  std::string_view name) noexcept
{
  std::lock_guard lock(mWriteMutex);
  auto pair = mTypeStorage.emplace(typeDieOffset, new sym::Type{ tag, dieReference, typeSize, name });
  if (pair.second) {
    return pair.first->second;
  }
  return nullptr;
}

sym::Type *
TypeStorage::FindTypeByOffset(u64 dieOffset) noexcept
{
  auto it = mTypeStorage.find(dieOffset);
  if (it != mTypeStorage.end()) {
    return it->second;
  }
  return nullptr;
}

namespace sym {

bool
Symbol::Computed() noexcept
{
  switch (mLocation->mKind) {
  case LocKind::DwarfExpression:
  case LocKind::LocationList:
    return true;
  case LocKind::UnreadLocationList:
    return false;
  }
}

std::span<const u8>
Symbol::GetDwarfExpression(AddrPtr programCounter) noexcept
{
  MDB_ASSERT(Computed(), "Symbol information not read in yet");
  switch (mLocation->mKind) {
  case LocKind::UnreadLocationList:
    break;
  case LocKind::DwarfExpression:
    return mLocation->uDwarfExpression;
  case LocKind::LocationList: {
    auto span = mLocation->uLocationList->Get();
    auto it = std::ranges::find_if(
      span, [programCounter](auto &r) { return r.mStart <= programCounter && programCounter <= r.mEnd; });
    if (it != std::end(span)) {
      return it->mDwarfExpression;
    }
  }
  }
  return {};
}

LocationList::LocationList(std::vector<LocationListEntry> &&entries) noexcept : mLocationList(std::move(entries))
{
}

std::span<const LocationListEntry>
LocationList::Get() noexcept
{
  return std::span{ mLocationList };
}

Type::Type(DwarfTag debugInfoEntryTag,
  dw::IndexedDieReference debugInfoEntryReference,
  u32 sizeOf,
  Type *target,
  bool isTypedef) noexcept
    : mName(target->mName), mCompUnitDieReference(debugInfoEntryReference),
      mModifier{ ToTypeModifierWillPanic(debugInfoEntryReference.GetDie()->mTag) }, mIsTypedef(isTypedef),
      size_of(sizeOf), mIsResolved(false), mIsProcessing(false), mTypeChain(target),
      mDebugInfoEntryTag(debugInfoEntryTag)
{
}

Type::Type(DwarfTag debugInfoEntryTag,
  dw::IndexedDieReference debugInfoEntryReference,
  u32 sizeOf,
  std::string_view name) noexcept
    : mName(name), mCompUnitDieReference(debugInfoEntryReference),
      mModifier{ ToTypeModifierWillPanic(debugInfoEntryReference.GetDie()->mTag) }, mIsTypedef(false),
      size_of(sizeOf), mIsResolved(false), mIsProcessing(false), mTypeChain(nullptr),
      mDebugInfoEntryTag(debugInfoEntryTag)
{
}

Type::Type(std::string_view name, size_t size) noexcept
    : mName(name), mModifier(Modifier::None), mIsTypedef(false), size_of(size), mIsResolved(true),
      mIsProcessing(false), mTypeChain(nullptr)
{
}

Type::Type(Type &&o) noexcept
    : mName(o.mName), mCompUnitDieReference(o.mCompUnitDieReference), mModifier(o.mModifier), size_of(o.size_of),
      mIsResolved(o.mIsResolved), mIsProcessing(o.mIsProcessing), mTypeChain(o.mTypeChain),
      mFields(std::move(o.mFields)), mBaseType(o.mBaseType)
{
  MDB_ASSERT(!mIsProcessing, "Moving a type that's being processed is guaranteed to have undefined behavior");
}

Type *
Type::ResolveAlias() noexcept
{
  if (!mIsTypedef) {
    return this;
  }
  Type *t = mTypeChain;
  while (t && t->mIsTypedef) {
    t = t->mTypeChain;
  }
  return t;
}

void
Type::SetBaseTypeEncoding(BaseTypeEncoding enc) noexcept
{
  mBaseType = enc;
}

void
Type::SetIsDeclaration() noexcept
{
  mIsDeclaration = true;
}

NonNullPtr<Type>
Type::GetTargetType() noexcept
{
  if (mTypeChain == nullptr) {
    return NonNull(*this);
  }
  Type *t = mTypeChain;
  while (t->mTypeChain) {
    t = t->mTypeChain;
  }
  return NonNull<Type>(*t);
}

bool
Type::IsReference() const noexcept
{
  auto mod = std::to_underlying(*mModifier);
  constexpr auto ReferenceEnd = std::to_underlying(Modifier::Atomic);
  constexpr auto ReferenceStart = std::to_underlying(Modifier::None);
  if (mod < ReferenceEnd && mod > ReferenceStart) {
    return true;
  }
  if (mTypeChain == nullptr) {
    return false;
  }
  Type *t = mTypeChain;
  while (t) {
    const auto mod = std::to_underlying(*t->mModifier);
    if (mod < ReferenceEnd && mod > ReferenceStart) {
      return true;
    }
    t = t->mTypeChain;
  }
  return false;
}

bool
Type::IsResolved() const noexcept
{
  if (mIsTypedef) {
    return mTypeChain->mIsResolved;
  }
  return mIsResolved;
}

u32
Type::Size() noexcept
{
  return size_of;
}

u32
Type::SizeBytes() noexcept
{
  if (mModifier == Modifier::Array) {
    auto bounds = Size();
    auto layout_type_size = TypeDescribingLayoutOfThis()->SkipJunk()->Size();
    return bounds * layout_type_size;
  }
  return Size();
}

std::optional<BaseTypeEncoding>
Type::GetBaseTypeIfPrimitive() const noexcept
{
  if (mBaseType.has_value() || mDebugInfoEntryTag == DwarfTag::DW_TAG_enumeration_type) {
    return mBaseType;
  }

  if (IsReference()) {
    return {};
  }

  Type *it = mTypeChain;
  while (it != nullptr) {
    if (it->mBaseType.has_value() || it->mDebugInfoEntryTag == DwarfTag::DW_TAG_enumeration_type) {
      return it->mBaseType;
    }
    it = it->mTypeChain;
  }
  return {};
}

bool
Type::IsPrimitive() const noexcept
{
  if (mBaseType.has_value() || mDebugInfoEntryTag == DwarfTag::DW_TAG_enumeration_type) {
    return true;
  }

  if (IsReference()) {
    return false;
  }

  auto it = mTypeChain;
  while (it != nullptr) {
    if (it->mBaseType.has_value() || it->mDebugInfoEntryTag == DwarfTag::DW_TAG_enumeration_type) {
      return true;
    }
    it = it->mTypeChain;
  }
  return false;
}

bool
Type::IsCharType() const noexcept
{
  return mBaseType
    .transform([](auto v) {
      switch (v) {
      case BaseTypeEncoding::DW_ATE_signed_char:
      case BaseTypeEncoding::DW_ATE_unsigned_char:
        return true;
      default:
        return false;
      }
    })
    .value_or(false);
}

bool
Type::IsArrayType() const noexcept
{
  if (!mIsTypedef) {
    return this->mModifier == Modifier::Array;
  }
  Type *t = mTypeChain;
  while (t->mIsTypedef) {
    t = t->mTypeChain;
  }
  return t->mModifier == Modifier::Array;
}

u32
Type::MembersCount() noexcept
{
  MDB_ASSERT(mIsResolved, "Type is not fully resolved!");
  return GetTargetType()->mFields.size();
}

std::span<const Field>
Type::MemberFields() noexcept
{
  MDB_ASSERT(mIsResolved, "Type is not fully resolved!");
  auto t = GetTargetType();
  return t->mFields;
}

Type *
Type::TypeDescribingLayoutOfThis() noexcept
{
  // We have to check if it's a typedef here too. const int& which is considered a reference in the type
  // information howoever using IntRef = const int&; makes IntRef have a modifier list of none, which is a DWARF
  // side effect, making type aliases behave as their own types, instead of just names.

  if (mModifier == Modifier::None && !mIsTypedef) {
    return SkipJunk();
  }

  Type *t = ResolveAlias();
  MDB_ASSERT(t, "Debug Symbolication Error: Resolving a typedef should not result in a nullptr for type.");
  if (t->IsReference()) {
    t = t->mTypeChain->ResolveAlias();
  }

  return t->SkipJunk();
}

void
Type::SetArrayBounds(u32 bounds) noexcept
{
  mArrayBounds = bounds;
}
} // namespace sym
} // namespace mdb