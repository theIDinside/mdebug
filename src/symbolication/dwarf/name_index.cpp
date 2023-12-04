#include "name_index.h"
#include "die.h"

namespace sym::dw {

bool
DieNameReference::is_valid() const
{
  if (cu == nullptr) {
    return die_index != 0;
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
NameIndex::add_name(std::string_view name, u32 die_index, UnitData *cu) noexcept
{
  // default constructs a DieNameReference{nullptr, 0} when mapping[name] doesn't exist
  // which DieNameReference::is_valid => false (i.e. mapping contains no `name` key)
  DLOG("dwarf", "adding {} for die #{} in Compilation Unit at offset {}", name, die_index, cu->section_offset());
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
    elem.die_index = die_index;
  }
}

void
NameIndex::convert_to_collision_variant(DieNameReference &elem, u32 die_index, UnitData *cu) noexcept
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
  DLOG("dwarf", "[name index: {}] Adding {} names", index_name, parsed_die_name_references.size());
  for (const auto &[name, idx, cu] : parsed_die_name_references) {
    add_name(name, idx, cu);
  }
}

NameIndex::FindResult
NameIndex::get_dies(std::string_view name) noexcept
{
  auto it = mapping.find(name);
  if (it == std::end(mapping))
    return FindResult{nullptr, 0};

  if (it->second.is_unique())
    return FindResult{&(it->second), 1};

  const auto collision_index = it->second.collision_displacement_index;
  auto &dies = colliding_die_name_refs[collision_index];
  return FindResult{dies.data(), static_cast<u32>(dies.size())};
}

} // namespace sym::dw