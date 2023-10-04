#pragma once
#include "symbol/dwarf/dwarf_defs.h"
#include "utils/static_vector.h"
#include <common.h>
#include <unordered_set>

namespace sym::dw2 {

class DwarfUnitData;
struct AttributeValue;
class UnitReader;
struct AbbreviationInfo;

// Represents an index value that points to nothing.
static constexpr auto NONE_INDEX = 0;

// Represents an invalid DIE or a DIE that not yet has been read in (or needs to be read in, again)
static constexpr auto INVALID_DIE = 0;

// Not the actual contents of a DIE, but is to be viewed more like a "coordinate" for a DIE and representing it's
// relationship with it's siblings, parent and children. This type _must_ live inside a vector. This vector of
// DIE's is parsed using DwarfUnitData::load_dies
struct DebugInfoEntry
{
  // Represents the UID for this die, as all dies in a .debug_info section will different relative offsets.
  u64 sec_offset : 37;
  // How many (sizeof(DebugInfoEntry) * parent_id) bytes back the parent DIE for this DIE can be found
  u64 parent_id : 24;
  // offset from `sec_offset` where actual die data begins, which is the first byte after the DIE tag and it's
  // abbreviation code (which is an ULEB128 - fucking hell, this seems irresponsibly stupid to use in 2023. What do
  // we save? 10%? 5%? 0? The complexity balloons, for no gain, alignment and all that good shit goes out of the
  // window. I suppose this is what happens when too smart people get to working on something.)
  // As such - we know the size of the dwarf TAG (because it's specified in the spec), so these bits represent the
  // length of the ULEB. So to get the offset, we do sizeof(DWARF_TAG) + die_data_offset.
  u64 die_data_offset : 3;
  u32 next_sibling : 31;
  u32 has_children : 1;
  u16 abbrev_code;
  DwarfTag tag;

  // Sets the .debug_info offset as this DIE's id.
  void set_id(u64 sec_offset_as_id) noexcept;

  // sets the parent's offset relative to this die in the vector containing all dies
  // thus, giving the ability to calculate parent by saying DebugInfoEntry* parent = (this - p_id);
  void set_parent_id(u64 p_id) noexcept;

  // sets the next sibling offset relative to this die in the vector containing all dies
  // thus, giving the ability to calculate next sibling by saying DebugInfoEntry* sib = (this + next_sibling);
  void set_sibling_id(u32 sib_id) noexcept;

  // Get (most closely) related DIE's.
  const DebugInfoEntry *parent() const noexcept;
  const DebugInfoEntry *sibling() const noexcept;
  const DebugInfoEntry *children() const noexcept;

  bool is_valid() const noexcept;
  static DebugInfoEntry create_cu(u64 sec_offset, u16 abbrev_code, DwarfTag tag, bool has_children) noexcept;
  static DebugInfoEntry create_die(u64 sec_offset, AbbreviationInfo &abbr, u64 parent_id, u64 die_data_offset,
                                   u64 next_sibling) noexcept;
};

// Determines if `entry` represents a variable that lives either in static or global scope.
bool is_super_scope_variable(const DebugInfoEntry &entry) noexcept;
std::optional<std::string_view> get_name(DwarfUnitData *cu, const DebugInfoEntry *entry) noexcept;

// An indexed die, is reached by using the `DW_AT_name` or the `DW_AT_linkage_name` attribute
struct DieKey
{
  using Set = std::unordered_set<u64>;
  u64 sec_offset;
  constexpr auto operator<=>(const DieKey &) const = default;
};

class DIEReference
{
public:
  explicit DIEReference() noexcept;
  explicit DIEReference(DwarfUnitData *containing_cu, DebugInfoEntry *entry) noexcept;
  explicit DIEReference(DwarfUnitData *containing_cu, const DebugInfoEntry *entry) noexcept;
  explicit DIEReference(const DwarfUnitData *containing_cu, DebugInfoEntry *entry) noexcept;
  explicit DIEReference(const DwarfUnitData *containing_cu, const DebugInfoEntry *entry) noexcept;

  bool is_valid() const noexcept;
  DwarfUnitData *get_cu() const noexcept;
  DebugInfoEntry *get_die() const noexcept;
  std::optional<AttributeValue> get_attribute(Attribute attr) noexcept;
  // returns a UnitReader that has skipped all data up to `attr` so that the next read will be the specified
  // attribute `attr`
  std::optional<UnitReader> get_attribute_reader(Attribute attr) noexcept;
  bool is_structured_type() const noexcept;
  bool is_member_fn() const noexcept;
  friend bool operator==(const DIEReference &lhs, const DIEReference &rhs) noexcept;
  std::optional<DIEReference> get_referenced_die(Attribute attribute) const noexcept;

private:
  DwarfUnitData *cu_data;
  DebugInfoEntry *entry;
};

//
// An iterator that takes in a DIE, and attempts to "walk upwards" the tree in a fashion that takes "Declarations
// Completing Non-Defining Declarations" into account Read: "2.13.2 Declarations Completing Non-Defining
// Declarations" in the DWARF spec: https://dwarfstd.org/doc/DWARF5.pdf It's technically, not a parent node, but it
// amounts to it, since we *require* that context in certain cases to make sense of the "current" DIE we're
// analyzing. Yet another wonderfully complex and seemingly bad design of DWARF. Is it the OOP-mindset? I'd argue
// it is. We'll dive into this at a later date, when we have a fully DWARF compliant parser, to see if we can't
// transform the DWARF format into something less "OOP-y" and see if our idea can translate into a more simple (and
// thus faster) format. For now, we have to deal with it.
class DIECompletingIterator
{
public:
  explicit DIECompletingIterator(DIEReference ref) noexcept;
  explicit DIECompletingIterator() noexcept;
  std::optional<DIEReference> next() noexcept;

private:
  utils::InlineVector<DIEReference, 5> dies_to_visit;
  utils::InlineVector<DIEReference, 5> visited_dies;
};

} // namespace sym::dw2