/** LICENSE TEMPLATE */
#include "die_ref.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf_attribute_value.h"
#include <limits>
#include <symbolication/dwarf/die.h>
#include <symbolication/objfile.h>

namespace mdb::sym::dw {

std::tuple<u64, const char *>
PrepareCompileUnitPreDwarf5(UnitData *compilationUnit, const DieMetaData &unitDie)
{
  MDB_ASSERT(compilationUnit && std::to_underlying(compilationUnit->GetHeader().Version()) < 5,
    "Expected compillation to not be null and version <= 4");
  UnitReader reader{ compilationUnit };
  reader.SeekDie(unitDie);
  const auto &attrs = compilationUnit->GetAbbreviation(unitDie.mAbbreviationCode);

  u64 offset = std::numeric_limits<u64>::max();
  const char *directory = nullptr;

  for (auto attribute : attrs.mAttributes) {
    switch (attribute.mName) {
    case Attribute::DW_AT_stmt_list: {
      const auto val = ReadAttributeValue(reader, attribute, attrs.mImplicitConsts);
      offset = val.AsUnsignedValue();
    } break;
    case Attribute::DW_AT_comp_dir: {
      const auto val = ReadAttributeValue(reader, attribute, attrs.mImplicitConsts);
      directory = val.AsCString();
    } break;
    default:
      reader.SkipAttribute(attribute);
    }
  }

  return std::tuple<u64, const char *>{ offset, directory };
}

DieReference::DieReference(UnitData *compilationUnit, const DieMetaData *die) noexcept
    : mUnitData(compilationUnit), mDebugInfoEntry(die)
{
}

UnitData *
DieReference::GetUnitData() const noexcept
{
  return mUnitData;
}

const DieMetaData *
DieReference::GetDie() const noexcept
{
  return mDebugInfoEntry;
}

DieReference
DieReference::MaybeResolveReference() const noexcept
{
  if (!mUnitData || !mDebugInfoEntry) {
    return DieReference{ nullptr, nullptr };
  }
  UnitReader reader{ mUnitData };
  const auto &attrs = mUnitData->GetAbbreviation(mDebugInfoEntry->mAbbreviationCode);
  reader.SeekDie(*mDebugInfoEntry);
  for (auto abbreviation : attrs.mAttributes) {
    switch (abbreviation.mName) {
    case Attribute::DW_AT_abstract_origin:
    case Attribute::DW_AT_specification: {
      const auto value = ReadAttributeValue(reader, abbreviation, {});
      auto offset = value.AsUnsignedValue();
      return mUnitData->GetObjectFile()->GetDieReference(offset);
    }
    default:
      reader.SkipAttribute(abbreviation);
    }
  }
  return DieReference{ nullptr, nullptr };
}

u64
DieReference::IndexOfDie() const noexcept
{
  return mUnitData->IndexOf(mDebugInfoEntry);
}

u64
DieReference::SectionOffset() const noexcept
{
  return mDebugInfoEntry->mSectionOffset;
}

bool
DieReference::TypeDieIsDeclaration() const noexcept
{
  switch (mDebugInfoEntry->mTag) {
  case DwarfTag::DW_TAG_class_type:
  case DwarfTag::DW_TAG_structure_type:
    break;
  default:
    return false;
  }

  if (auto v = ReadAttribute(Attribute::DW_AT_declaration); v.has_value()) {
    MDB_ASSERT(v->AsUnsignedValue() > 0, "Declaration flag, but 0?");
    return v->AsUnsignedValue() > 0;
  }

  return false;
}

const AbbreviationInfo &
DieReference::GetAbbreviation() const noexcept
{
  return mUnitData->GetAbbreviation(mDebugInfoEntry->mAbbreviationCode);
}

bool
DieReference::IsValid() const noexcept
{
  return mUnitData != nullptr && mDebugInfoEntry != nullptr;
}

IndexedDieReference::IndexedDieReference(const DieReference &reference) noexcept
{
  mUnitData = reference.GetUnitData();
  mDieIndex = reference.IndexOfDie();
}

IndexedDieReference::IndexedDieReference(UnitData *compilationUnit, u64 index) noexcept
    : mUnitData(compilationUnit), mDieIndex(index)
{
}

bool
IndexedDieReference::IsValid() const noexcept
{
  return mUnitData != nullptr;
}

IndexedDieReference
DieReference::AsIndexed() const noexcept
{
  return IndexedDieReference{ mUnitData, mUnitData->IndexOf(mDebugInfoEntry) };
}

UnitReader
DieReference::GetReader() const noexcept
{
  return UnitReader{ mUnitData, *mDebugInfoEntry };
}

std::optional<DieReference>
DieReference::GetParent() const
{
  const DieMetaData *parent = mDebugInfoEntry->GetParent();
  if (!parent) {
    return std::nullopt;
  }
  return DieReference{ mUnitData, parent };
}

std::optional<AttributeValue>
DieReference::ReadAttribute(Attribute attr) const noexcept
{
  UnitReader reader{ mUnitData };
  const auto &attrs = mUnitData->GetAbbreviation(mDebugInfoEntry->mAbbreviationCode);
  reader.SeekDie(*mDebugInfoEntry);
  long i = 0;
  for (auto attribute : attrs.mAttributes) {
    if (attribute.mName == attr) {
      reader.SkipAttributes(std::span{ attrs.mAttributes.begin(), attrs.mAttributes.begin() + i });
      return ReadAttributeValue(reader, attribute, attrs.mImplicitConsts);
    }
    ++i;
  }
  return std::nullopt;
}

UnitData *
IndexedDieReference::GetUnitData() const noexcept
{
  return mUnitData;
}

u64
IndexedDieReference::GetIndex() const noexcept
{
  return mDieIndex;
}

const DieMetaData *
IndexedDieReference::GetDie() noexcept
{
  return &mUnitData->GetDies()[mDieIndex];
}

DieReference
IndexedDieReference::ToDieReference() const
{
  const DieMetaData *die = const_cast<IndexedDieReference &>(*this).GetDie();
  return DieReference{ mUnitData, die };
}
} // namespace mdb::sym::dw