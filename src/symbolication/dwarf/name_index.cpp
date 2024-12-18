#include "name_index.h"
#include "die.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include <symbolication/objfile.h>

namespace sym::dw {

bool
DieNameReference::is_valid() const
{
  if (cu == nullptr) {
    return die_index.value() != 0;
  }
  return true;
}

bool
DieNameReference::is_unique() const noexcept
{
  return unique != 0xff'ff'ff'ff;
}

void
DieNameReference::set_as_collision_variant(u32 index) noexcept
{
  unique = 0xff'ff'ff'ff;
  collision_displacement_index = index;
  ASSERT(is_valid(), "We fucked up our own invariants");
}

void
DieNameReference::set_not_unique() noexcept
{
  unique = 0xff'ff'ff'ff;
}

void
DieNameReference::set_collision_index(u32 index) noexcept
{
  collision_displacement_index = index;
}

NameIndex::NameIndex(std::string_view name) noexcept
    : index_name(name), mutex(), mapping(), colliding_die_name_refs()
{
}

void
NameIndex::add_name(std::string_view name, Index die_index, UnitData *cu) noexcept
{
  auto &elem = mapping[name];
  if (elem.is_valid()) {
    if (elem.is_unique()) {
      convert_to_collision_variant(elem, die_index, cu);
    } else {
      auto &collisions = colliding_die_name_refs[elem.collision_displacement_index];
      collisions.push_back(DieNameReference{cu, die_index});
    }
  } else {
    elem.cu = cu;
    elem.die_index = Index{die_index};
  }
}

void
NameIndex::convert_to_collision_variant(DieNameReference &elem, Index die_index, UnitData *cu) noexcept
{
  const auto index = colliding_die_name_refs.size();
  colliding_die_name_refs.push_back({});
  auto &collisions = colliding_die_name_refs.back();
  collisions.push_back(DieNameReference{elem.cu, elem.die_index});
  collisions.push_back(DieNameReference{cu, die_index});
  elem.set_as_collision_variant(index);
}

void
NameIndex::merge(const std::vector<NameIndex::NameDieTuple> &parsed_die_name_references) noexcept
{
  std::lock_guard lock(mutex);
  DBGLOG(dwarf, "[name index: {}] Adding {} names", index_name, parsed_die_name_references.size());
  for (const auto &[name, idx, cu] : parsed_die_name_references) {
    add_name(name, idx, cu);
  }
}

void
NameIndex::merge_types(ObjectFile *obj, const std::vector<NameDieTuple> &parsed_die_name_references) noexcept
{
  std::lock_guard lock(mutex);
  DBGLOG(dwarf, "[name index: {}] Adding {} names", index_name, parsed_die_name_references.size());
  for (const auto &[name, idx, cu] : parsed_die_name_references) {
    add_name(name, idx, cu);
    const auto die_ref = cu->get_cu_die_ref(idx);
    const auto this_die = die_ref.GetDie();
    if (this_die->tag == DwarfTag::DW_TAG_typedef || this_die->tag == DwarfTag::DW_TAG_array_type) {
      continue;
    }
    const auto offs = Offset{die_ref.GetDie()->section_offset};
    const auto possible_size = die_ref.read_attribute(Attribute::DW_AT_byte_size);
    ASSERT(possible_size.has_value(), "Expected a 'root' die for a type to have a byte size cu=0x{:x}, die=0x{:x}",
           cu->section_offset(), die_ref.GetDie()->section_offset);
    auto type = obj->GetTypeStorage()->CreateNewType(this_die->tag, offs, IndexedDieReference{cu, idx},
                                         possible_size->unsigned_value(), name);
    if (die_ref.GetDie()->tag == DwarfTag::DW_TAG_base_type) {
      UnitReader reader{cu};
      reader.seek_die(*die_ref.GetDie());
      auto attr = die_ref.read_attribute(Attribute::DW_AT_encoding);
      ASSERT(attr.has_value(), "Failed to read encoding of base type. cu=0x{:x}, die=0x{:x}", cu->section_offset(),
             die_ref.GetDie()->section_offset);
      auto encoding =
        attr.and_then([](auto val) { return std::optional{static_cast<BaseTypeEncoding>(val.unsigned_value())}; });
      type->SetBaseTypeEncoding(encoding.value());
    }
  }
}

std::optional<std::span<const DieNameReference>>
NameIndex::search(std::string_view name) const noexcept
{
  auto it = mapping.find(name);
  if (it == std::end(mapping)) {
    return std::nullopt;
  }

  if (it->second.is_unique()) {
    return std::span{&(it->second), 1};
  }

  const auto collision_index = it->second.collision_displacement_index;
  auto &dies = colliding_die_name_refs[collision_index];
  return std::span{dies};
}

NameIndex::FindResult
NameIndex::get_dies(std::string_view name) noexcept
{
  auto it = mapping.find(name);
  if (it == std::end(mapping)) {
    return FindResult{nullptr, 0};
  }

  if (it->second.is_unique()) {
    return FindResult{&(it->second), 1};
  }

  const auto collision_index = it->second.collision_displacement_index;
  auto &dies = colliding_die_name_refs[collision_index];
  return FindResult{dies.data(), static_cast<u32>(dies.size())};
}

} // namespace sym::dw