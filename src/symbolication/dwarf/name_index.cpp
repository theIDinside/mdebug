/** LICENSE TEMPLATE */
#include "name_index.h"
#include "die.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include <symbolication/objfile.h>

namespace mdb::sym::dw {

bool
DieNameReference::IsValid() const
{
  if (cu == nullptr) {
    return die_index != 0;
  }
  return true;
}

bool
DieNameReference::IsUnique() const noexcept
{
  return unique != 0xff'ff'ff'ff;
}

void
DieNameReference::SetAsCollisionVariant(u64 index) noexcept
{
  unique = 0xff'ff'ff'ff;
  collision_displacement_index = index;
  ASSERT(IsValid(), "We fucked up our own invariants");
}

void
DieNameReference::SetNotUnique() noexcept
{
  unique = 0xff'ff'ff'ff;
}

void
DieNameReference::SetCollisionIndex(u64 index) noexcept
{
  collision_displacement_index = index;
}

NameIndex::NameIndex(std::string_view name) noexcept
    : index_name(name), mutex(), mapping(), colliding_die_name_refs()
{
}

void
NameIndex::AddName(const char *name, u64 die_index, UnitData *cu) noexcept
{
  auto &elem = mapping[name];
  if (elem.IsValid()) {
    if (elem.IsUnique()) {
      ConvertToCollisionVariant(elem, die_index, cu);
    } else {
      auto &collisions = colliding_die_name_refs[elem.collision_displacement_index];
      collisions.push_back(DieNameReference{cu, die_index});
    }
  } else {
    elem.cu = cu;
    elem.die_index = die_index;
  }
}

void
NameIndex::ConvertToCollisionVariant(DieNameReference &elem, u64 die_index, UnitData *cu) noexcept
{
  const auto index = colliding_die_name_refs.size();
  colliding_die_name_refs.push_back({});
  auto &collisions = colliding_die_name_refs.back();
  collisions.push_back(DieNameReference{elem.cu, elem.die_index});
  collisions.push_back(DieNameReference{cu, die_index});
  elem.SetAsCollisionVariant(index);
}

void
NameIndex::Merge(const std::vector<NameIndex::NameDieTuple> &parsed_die_name_references) noexcept
{
  std::lock_guard lock(mutex);
  DBGLOG(dwarf, "[name index: {}] Adding {} names", index_name, parsed_die_name_references.size());
  for (const auto &[name, idx, cu] : parsed_die_name_references) {
    AddName(name, idx, cu);
  }
}

void
NameIndex::MergeTypes(NonNullPtr<TypeStorage> typeStorage,
                      const std::vector<NameTypeDieTuple> &parsed_die_name_references) noexcept
{
  std::lock_guard lock(mutex);
  DBGLOG(dwarf, "[name index: {}] Adding {} names", index_name, parsed_die_name_references.size());
  for (const auto &[name, idx, cu, hash] : parsed_die_name_references) {
    AddName(name, idx, cu);
    const auto die_ref = cu->GetDieByCacheIndex(idx);
    const auto this_die = die_ref.GetDie();
    if (this_die->mTag == DwarfTag::DW_TAG_typedef || this_die->mTag == DwarfTag::DW_TAG_array_type) {
      continue;
    }
    const auto offs = Offset{die_ref.GetDie()->mSectionOffset};
    const auto possible_size = die_ref.ReadAttribute(Attribute::DW_AT_byte_size);
    ASSERT(possible_size.has_value(), "Expected a 'root' die for a type to have a byte size cu=0x{:x}, die=0x{:x}",
           cu->SectionOffset(), die_ref.GetDie()->mSectionOffset);

    auto type = typeStorage->CreateNewType(this_die->mTag, offs, IndexedDieReference{cu, idx},
                                           possible_size->AsUnsignedValue(), name);
    if (die_ref.GetDie()->mTag == DwarfTag::DW_TAG_base_type) {
      UnitReader reader{cu};
      reader.SeekDie(*die_ref.GetDie());
      auto attr = die_ref.ReadAttribute(Attribute::DW_AT_encoding);
      ASSERT(attr.has_value(), "Failed to read encoding of base type. cu=0x{:x}, die=0x{:x}", cu->SectionOffset(),
             die_ref.GetDie()->mSectionOffset);
      auto encoding = attr.and_then(
        [](auto val) { return std::optional{static_cast<BaseTypeEncoding>(val.AsUnsignedValue())}; });
      type->SetBaseTypeEncoding(encoding.value());
    }
  }
}

std::optional<std::span<const DieNameReference>>
NameIndex::Search(std::string_view name) const noexcept
{
  auto it = mapping.find(name);
  if (it == std::end(mapping)) {
    return std::nullopt;
  }

  if (it->second.IsUnique()) {
    return std::span{&(it->second), 1};
  }

  const auto collision_index = it->second.collision_displacement_index;
  auto &dies = colliding_die_name_refs[collision_index];
  return std::span{dies};
}

NameIndex::FindResult
NameIndex::GetDies(std::string_view name) noexcept
{
  auto it = mapping.find(name);
  if (it == std::end(mapping)) {
    return FindResult{nullptr, 0};
  }

  if (it->second.IsUnique()) {
    return FindResult{&(it->second), 1};
  }

  const auto collision_index = it->second.collision_displacement_index;
  auto &dies = colliding_die_name_refs[collision_index];
  return FindResult{dies.data(), static_cast<u32>(dies.size())};
}

} // namespace mdb::sym::dw