/** LICENSE TEMPLATE */
#include "die_ref.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf_attribute_value.h"
#include <limits>
#include <symbolication/dwarf/die.h>
#include <symbolication/objfile.h>

namespace mdb::sym::dw {

std::tuple<u64, const char *>
PrepareCompileUnitPreDwarf5(UnitData *cu, const DieMetaData &unitDie)
{
  ASSERT(cu && std::to_underlying(cu->header().Version()) < 5,
         "Expected compillation to not be null and version <= 4");
  UnitReader reader{cu};
  reader.SeekDie(unitDie);
  const auto &attrs = cu->GetAbbreviation(unitDie.mAbbreviationCode);

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

  return std::tuple<u64, const char *>{offset, directory};
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
    return DieReference{nullptr, nullptr};
  }
  UnitReader reader{mUnitData};
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
  return DieReference{nullptr, nullptr};
}

u64
DieReference::IndexOfDie() const noexcept
{
  return mUnitData->index_of(mDebugInfoEntry);
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
  return IndexedDieReference{mUnitData, mUnitData->index_of(mDebugInfoEntry)};
}

UnitReader
DieReference::GetReader() const noexcept
{
  return UnitReader{mUnitData, *mDebugInfoEntry};
}

std::optional<AttributeValue>
DieReference::ReadAttribute(Attribute attr) const noexcept
{
  UnitReader reader{mUnitData};
  const auto &attrs = mUnitData->GetAbbreviation(mDebugInfoEntry->mAbbreviationCode);
  reader.SeekDie(*mDebugInfoEntry);
  auto i = 0u;
  for (auto attribute : attrs.mAttributes) {
    if (attribute.mName == attr) {
      reader.SkipAttributes(std::span{attrs.mAttributes.begin(), attrs.mAttributes.begin() + i});
      return ReadAttributeValue(reader, attribute, attrs.mImplicitConsts);
    } else {
      ++i;
    }
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
} // namespace mdb::sym::dw