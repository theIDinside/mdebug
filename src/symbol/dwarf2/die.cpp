#include "die.h"
#include "symbol/dwarf/dwarf_defs.h"
#include "symbol/dwarf2/unit.h"
#include <algorithm>
#include <symbol/objfile.h>

namespace sym::dw2 {

DIEReference::DIEReference() noexcept : cu_data(nullptr), entry(nullptr) {}

DIEReference::DIEReference(DwarfUnitData *containing_cu, DebugInfoEntry *entry) noexcept
    : cu_data(containing_cu), entry(entry)
{
}

DIEReference::DIEReference(DwarfUnitData *containing_cu, const DebugInfoEntry *entry) noexcept
    : cu_data(containing_cu), entry(const_cast<DebugInfoEntry *>(entry))
{
}

DIEReference::DIEReference(const DwarfUnitData *containing_cu, DebugInfoEntry *entry) noexcept
    : cu_data(const_cast<DwarfUnitData *>(containing_cu)), entry(entry)
{
}

DIEReference::DIEReference(const DwarfUnitData *containing_cu, const DebugInfoEntry *entry) noexcept
    : cu_data(const_cast<DwarfUnitData *>(containing_cu)), entry(const_cast<DebugInfoEntry *>(entry))
{
}

bool
DIEReference::is_valid() const noexcept
{
  return (cu_data != nullptr) && (entry != nullptr);
}

DwarfUnitData *
DIEReference::get_cu() const noexcept
{
  return cu_data;
}

DebugInfoEntry *
DIEReference::get_die() const noexcept
{
  return entry;
}

/*static*/
DebugInfoEntry
DebugInfoEntry::create_cu(u64 sec_offset, u16 abbrev_code, DwarfTag tag, bool has_children) noexcept
{
  return DebugInfoEntry{sec_offset, NONE_INDEX, 0, NONE_INDEX, has_children, abbrev_code, tag};
}

/*static*/
DebugInfoEntry
DebugInfoEntry::create_die(u64 sec_offset, AbbreviationInfo &abbr, u64 parent_id, u64 die_data_offset,
                           u64 next_sibling) noexcept
{
  return DebugInfoEntry{sec_offset,        parent_id,
                        die_data_offset,   static_cast<u32>(next_sibling),
                        abbr.has_children, static_cast<u16>(abbr.code),
                        abbr.tag};
}

void
DebugInfoEntry::set_id(u64 sec_offset_as_id) noexcept
{
  sec_offset = sec_offset_as_id;
}

void
DebugInfoEntry::set_parent_id(u64 p_id) noexcept
{
  parent_id = p_id;
}

void
DebugInfoEntry::set_sibling_id(u32 sib_id) noexcept
{
  next_sibling = sib_id;
}

const DebugInfoEntry *
DebugInfoEntry::parent() const noexcept
{
  if (parent_id == 0)
    return nullptr;
  return (this - parent_id);
}

const DebugInfoEntry *
DebugInfoEntry::sibling() const noexcept
{
  if (next_sibling == 0)
    return nullptr;
  return (this + next_sibling);
}

const DebugInfoEntry *
DebugInfoEntry::children() const noexcept
{
  if (!has_children)
    return nullptr;
  return (this + 1);
}

bool
DebugInfoEntry::is_valid() const noexcept
{
  return sec_offset != INVALID_DIE;
}

bool
is_super_scope_variable(const DebugInfoEntry &entry) noexcept
{
  using enum DwarfTag;
  if (entry.tag != DW_TAG_variable)
    return false;

  auto parent = entry.parent();
  while (parent != nullptr) {
    switch (parent->tag) {
    case DW_TAG_subprogram:
    case DW_TAG_lexical_block:
    case DW_TAG_inlined_subroutine:
      return false;
    case DW_TAG_compile_unit:
    case DW_TAG_partial_unit:
      return true;
    default:
      break;
    }
    parent = parent->parent();
  }
  return false;
}

std::optional<AttributeValue>
DIEReference::get_attribute(Attribute attribute) noexcept
{
  const auto &abbr = cu_data->get_abbreviation_set(entry->abbrev_code);
  UnitReader reader{get_cu(), get_die()};
  int idx = 0;
  for (const auto &attr : abbr.attributes) {
    if (attr.name == attribute) {
      std::span attrs{abbr.attributes.begin(), abbr.attributes.begin() + idx};
      reader.skip_attributes(attrs);
      std::vector<i64> ic{};
      return read_attribute_value(reader, attr, ic);
    }
    idx++;
  }
  return std::nullopt;
}

std::optional<UnitReader>
DIEReference::get_attribute_reader(Attribute attribute) noexcept
{
  const auto &abbr = cu_data->get_abbreviation_set(entry->abbrev_code);
  UnitReader reader{get_cu(), get_die()};
  int idx = 0;
  for (const auto &attr : abbr.attributes) {
    if (attr.name == attribute) {
      std::span attrs{abbr.attributes.begin(), abbr.attributes.begin() + idx};
      reader.skip_attributes(attrs);
      return std::optional{reader};
    }
    idx++;
  }
  return std::nullopt;
}

bool
DIEReference::is_structured_type() const noexcept
{
  const auto parent_tag = entry->parent()->tag;
  return (parent_tag == DwarfTag::DW_TAG_structure_type) || (parent_tag == DwarfTag::DW_TAG_union_type) ||
         (parent_tag == DwarfTag::DW_TAG_class_type);
}

bool
DIEReference::is_member_fn() const noexcept
{
  DIECompletingIterator iter(*this);
  while (auto die_ref = iter.next()) {
    if (die_ref->is_structured_type()) {
      return true;
    }
  }
  return false;
}

std::optional<std::string_view>
get_name(DwarfUnitData *cu, const DebugInfoEntry *entry) noexcept
{
  return DIEReference{cu, entry}.get_attribute(Attribute::DW_AT_name).transform([](auto &&v) {
    return v.string();
  });
}

bool
operator==(const DIEReference &lhs, const DIEReference &rhs) noexcept
{
  return lhs.get_die() == rhs.get_die() && lhs.get_cu() == rhs.get_cu();
}

std::optional<DIEReference>
DIEReference::get_referenced_die(Attribute attribute) const noexcept
{
  ASSERT(attribute == Attribute::DW_AT_abstract_origin || attribute == Attribute::DW_AT_specification,
         "Wrong attribute; it doesn't represent a referencing attribute: {}", to_str(attribute));
  auto cu = cu_data;
  auto e = entry;
  auto &abbr = cu->get_abbreviation_set(e->abbrev_code);
  return abbr.find_abbreviation_indexed(attribute).transform(
      [cu, e, &abbr](std::tuple<int, Abbreviation> &&tuple) -> DIEReference {
        const auto &[index, abbrev] = tuple;
        UnitReader reader{cu, e};
        std::span attrs{abbr.attributes.begin(), abbr.attributes.begin() + index};
        reader.skip_attributes(attrs);
        std::vector<i64> ignore{};
        const auto value = read_attribute_value(reader, abbrev, ignore).unsigned_value();
        if (abbrev.form == AttributeForm::DW_FORM_ref_addr) {
          const auto id = DwarfId(value);
          auto new_cu = cu->get_objfile()->get_containing_cu(id);
          auto die = new_cu->get_die(id);
          return DIEReference(new_cu, die);
        } else {
          auto die = cu->get_die(DwarfId(value));
          return DIEReference{cu, die};
        }
      });
}

DIECompletingIterator::DIECompletingIterator(DIEReference ref) noexcept : dies_to_visit(), visited_dies()
{
  dies_to_visit.push_back(ref);
}

DIECompletingIterator::DIECompletingIterator() noexcept : dies_to_visit(), visited_dies() {}

std::optional<DIEReference>
DIECompletingIterator::next() noexcept
{
  if (dies_to_visit.empty())
    return std::nullopt;
  const auto die = dies_to_visit.pop_back();
  visited_dies.push_back(die);
  for (auto attr : {Attribute::DW_AT_specification, Attribute::DW_AT_abstract_origin}) {
    if (const auto referenced = die.get_referenced_die(attr); referenced) {
      if (!visited_dies.contains(referenced.value()))
        dies_to_visit.push_back(*referenced);
    }
  }
  return die;
}

} // namespace sym::dw2