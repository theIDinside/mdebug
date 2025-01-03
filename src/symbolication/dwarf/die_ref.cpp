#include "die_ref.h"
#include "symbolication/dwarf.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include <limits>
#include <symbolication/dwarf/die.h>
#include <symbolication/objfile.h>

namespace sym::dw {

std::tuple<u64, const char *>
PrepareCompileUnitPreDwarf5(UnitData *cu, const DieMetaData &unitDie)
{
  ASSERT(cu && std::to_underlying(cu->header().version()) < 5, "Expected compillation to not be null and version <= 4");
  UnitReader reader{cu};
  reader.SeekDie(unitDie);
  const auto &attrs = cu->get_abbreviation(unitDie.abbreviation_code);

  u64 offset = std::numeric_limits<u64>::max();
  const char *directory = nullptr;

  for (auto attribute : attrs.attributes) {
    switch (attribute.name) {
    case Attribute::DW_AT_stmt_list: {
      const auto val = read_attribute_value(reader, attribute, attrs.implicit_consts);
      offset = val.unsigned_value();
    } break;
    case Attribute::DW_AT_comp_dir: {
      const auto val = read_attribute_value(reader, attribute, attrs.implicit_consts);
      directory = val.string();
    } break;
    default:
      reader.skip_attribute(attribute);
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
  const auto &attrs = mUnitData->get_abbreviation(mDebugInfoEntry->abbreviation_code);
  reader.SeekDie(*mDebugInfoEntry);
  for (auto abbreviation : attrs.attributes) {
    switch (abbreviation.name) {
    case Attribute::DW_AT_abstract_origin:
    case Attribute::DW_AT_specification: {
      const auto value = read_attribute_value(reader, abbreviation, {});
      auto offset = value.unsigned_value();
      return mUnitData->GetObjectFile()->GetDieReference(offset);
    }
    default:
      reader.skip_attribute(abbreviation);
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
  return mUnitData->get_abbreviation(mDebugInfoEntry->abbreviation_code);
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
DieReference::read_attribute(Attribute attr) const noexcept
{
  UnitReader reader{mUnitData};
  const auto &attrs = mUnitData->get_abbreviation(mDebugInfoEntry->abbreviation_code);
  reader.SeekDie(*mDebugInfoEntry);
  auto i = 0u;
  for (auto attribute : attrs.attributes) {
    if (attribute.name == attr) {
      reader.skip_attributes(std::span{attrs.attributes.begin(), attrs.attributes.begin() + i});
      return read_attribute_value(reader, attribute, attrs.implicit_consts);
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
  return &mUnitData->get_dies()[mDieIndex];
}
} // namespace sym::dw