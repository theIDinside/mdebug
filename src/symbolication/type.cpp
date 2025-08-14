/** LICENSE TEMPLATE */
#include "type.h"
#include "dwarf_attribute_value.h"
#include "symbolication/dwarf/attribute_read.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/die_iterator.h"
#include "symbolication/dwarf_defs.h"
#include <algorithm>
#include <optional>
#include <supervisor.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/objfile.h>
#include <utility>
namespace mdb {
static constexpr bool
IsNotCompleteTypeDie(const sym::dw::DieMetaData *die)
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
  ASSERT(array_die.GetDie()->mHasChildren, "expected die {} to have children", array_die);

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

sym::Type *
TypeStorage::GetOrCreateNewType(sym::dw::IndexedDieReference die_ref) noexcept
{
  const sym::dw::DieReference this_ref{ die_ref.GetUnitData(), die_ref.GetDie() };
  const auto type_id = this_ref.GetDie()->mSectionOffset;

  if (mTypeStorage.contains(type_id)) {
    auto t = mTypeStorage[type_id];
    return t;
  }

  if (IsNotCompleteTypeDie(this_ref.GetDie())) {
    const auto attr = this_ref.ReadAttribute(Attribute::DW_AT_type);
    auto base_type =
      attr.transform([](auto v) { return v.AsUnsignedValue(); })
        .and_then(
          [&](auto offset) { return die_ref.GetUnitData()->GetObjectFile()->GetDebugInfoEntryReference(offset); })
        .transform([this](auto other_cu_die) { return GetOrCreateNewType(other_cu_die.AsIndexed()); })
        .or_else([this]() -> std::optional<sym::Type *> { return GetUnitType(); })
        .value();
    auto size = 0u;
    auto array_bounds = 0u;
    // TODO(simon): We only support 64-bit machines right now. Therefore all non-value types/reference-like types
    // are 8 bytes large
    if (sym::IsReferenceLike(this_ref.GetDie()) || base_type->IsReference()) {
      if (this_ref.GetDie()->mTag == DwarfTag::DW_TAG_array_type) {
        array_bounds = ResolveArrayBounds(this_ref);
      }
      size = REFERENCE_SIZE;
    } else {
      size = base_type->Size();
    }

    auto type = new sym::Type{
      this_ref.GetDie()->mTag, die_ref, size, base_type, this_ref.GetDie()->mTag == DwarfTag::DW_TAG_typedef
    };
    type->SetArrayBounds(array_bounds);
    mTypeStorage[this_ref.GetDie()->mSectionOffset] = type;
    return type;
  } else {
    if (const auto &attr_val = this_ref.ReadAttribute(Attribute::DW_AT_signature); attr_val) {
      // DWARF5 support; we might run into type units, therefore we have to resolve the *actual* die we want here
      // yet we still want to map this_ref's die offset to the type. This is unfortunate, since we might get
      // "copies" i.e. mulitple die's that have a ref signature. The actual backing data is just 1 of though, so it
      // just means mulitple keys can reach the value, which is a pointer to the actual type.
      auto tu_die_ref =
        this_ref.GetUnitData()->GetObjectFile()->GetTypeUnitTypeDebugInfoEntry(attr_val->AsUnsignedValue());
      ASSERT(tu_die_ref.IsValid(), "expected die reference to type unit to be valid");
      const u32 sz = tu_die_ref.ReadAttribute(Attribute::DW_AT_byte_size)->AsUnsignedValue();
      const auto name = tu_die_ref.ReadAttribute(Attribute::DW_AT_name)
                          .transform(AttributeValue::ToStringView)
                          .value_or("<no name>");
      auto type = new sym::Type{ this_ref.GetDie()->mTag, tu_die_ref.AsIndexed(), sz, name };
      mTypeStorage[this_ref.GetDie()->mSectionOffset] = type;
      return type;
    } else {
      // lambdas have no assigned type name in DWARF (C++). That's just nutter butter shit.
      // Like come on dog. Give it a bogus name, whatever really. But nothing?
      const auto name = this_ref.ReadAttribute(Attribute::DW_AT_name)
                          .transform([](auto v) { return v.AsStringView(); })
                          .value_or("lambda");
      const u32 sz =
        this_ref.ReadAttribute(Attribute::DW_AT_byte_size).transform(AttributeValue::AsUnsigned).value_or(0);
      auto type = new sym::Type{ this_ref.GetDie()->mTag, die_ref, sz, name };
      mTypeStorage[this_ref.GetDie()->mSectionOffset] = type;
      return type;
    }
  }
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
  ASSERT(Computed(), "Symbol information not read in yet");
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
      size_of(sizeOf), mIsResolved(false), mIsProcessing(false), mTypeChain(target), mFields(), mBaseTypes(),
      mDebugInfoEntryTag(debugInfoEntryTag)
{
}

Type::Type(DwarfTag debugInfoEntryTag,
  dw::IndexedDieReference debugInfoEntryReference,
  u32 sizeOf,
  std::string_view name) noexcept
    : mName(name), mCompUnitDieReference(debugInfoEntryReference),
      mModifier{ ToTypeModifierWillPanic(debugInfoEntryReference.GetDie()->mTag) }, mIsTypedef(false),
      size_of(sizeOf), mIsResolved(false), mIsProcessing(false), mTypeChain(nullptr), mFields(), mBaseTypes(),
      mDebugInfoEntryTag(debugInfoEntryTag)
{
}

Type::Type(std::string_view name, size_t size) noexcept
    : mName(name), mCompUnitDieReference(), mModifier(Modifier::None), mIsTypedef(false), size_of(size),
      mIsResolved(true), mIsProcessing(false), mTypeChain(nullptr), mFields(), mBaseTypes()
{
}

Type::Type(Type &&o) noexcept
    : mName(o.mName), mCompUnitDieReference(o.mCompUnitDieReference), mModifier(o.mModifier), size_of(o.size_of),
      mIsResolved(o.mIsResolved), mIsProcessing(o.mIsProcessing), mTypeChain(o.mTypeChain),
      mFields(std::move(o.mFields)), mBaseTypes(o.mBaseTypes)
{
  ASSERT(!mIsProcessing, "Moving a type that's being processed is guaranteed to have undefined behavior");
}

Type *
Type::ResolveAlias() noexcept
{
  if (!mIsTypedef) {
    return this;
  }
  auto t = mTypeChain;
  while (t && t->mIsTypedef) {
    t = t->mTypeChain;
  }
  return t;
}

void
Type::SetBaseTypeEncoding(BaseTypeEncoding enc) noexcept
{
  mBaseTypes = enc;
}

NonNullPtr<Type>
Type::GetTargetType() noexcept
{
  if (mTypeChain == nullptr) {
    return NonNull(*this);
  }
  auto t = mTypeChain;
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
  auto t = mTypeChain;
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
    auto layout_type_size = TypeDescribingLayoutOfThis()->Size();
    return bounds * layout_type_size;
  } else {
    return Size();
  }
}

bool
Type::IsPrimitive() const noexcept
{
  if (mBaseTypes.has_value() || mDebugInfoEntryTag == DwarfTag::DW_TAG_enumeration_type) {
    return true;
  }

  if (IsReference()) {
    return false;
  }

  auto it = mTypeChain;
  while (it != nullptr) {
    if (it->mBaseTypes.has_value() || it->mDebugInfoEntryTag == DwarfTag::DW_TAG_enumeration_type) {
      return true;
    }
    it = it->mTypeChain;
  }
  return false;
}

bool
Type::IsCharType() const noexcept
{
  return mBaseTypes
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
  auto t = mTypeChain;
  while (t->mIsTypedef) {
    t = t->mTypeChain;
  }
  return t->mModifier == Modifier::Array;
}

u32
Type::MembersCount() noexcept
{
  ASSERT(mIsResolved, "Type is not fully resolved!");
  return GetTargetType()->mFields.size();
}

const std::vector<Field> &
Type::MemberFields() noexcept
{
  ASSERT(mIsResolved, "Type is not fully resolved!");
  auto t = GetTargetType();
  return t->mFields;
}

Type *
Type::TypeDescribingLayoutOfThis() noexcept
{
  if (mModifier == Modifier::None) {
    return this;
  }

  if (auto t = ResolveAlias(); t->IsReference()) {
    t = t == this ? t->mTypeChain : t;
    while (!t->IsReference() && t->mModifier != Modifier::None) {
      t = t->mTypeChain->ResolveAlias();
    }
    return t;
  } else {
    auto it = mTypeChain;
    while (it != nullptr) {
      if (it->mModifier == Modifier::None) {
        return it;
      }
      it = it->mTypeChain;
    }
  }

  return nullptr;
}

void
Type::SetArrayBounds(u32 bounds) noexcept
{
  mArrayBounds = bounds;
}
} // namespace sym
} // namespace mdb