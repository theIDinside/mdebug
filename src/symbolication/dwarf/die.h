#pragma once
#include "common.h"
#include <symbolication/block.h>
#include <symbolication/dwarf.h>
#include <utils/indexing.h>

struct ObjectFile;
struct ElfSection;

namespace sym::dw {

// Represents an index value that points to nothing.
static constexpr auto NONE_INDEX = 0;

// Represents an invalid DIE or a DIE that not yet has been read in (or needs to be read in, again)
static constexpr auto INVALID_DIE = 0;

struct Abbreviation
{
  Attribute name;
  AttributeForm form;
  // An index into a IMPLICIT_CONST table for this abbreviation table
  // This is solely done for space reasons, instead of paying the cost of 64 bits for every
  // Abbreviation. Let's hope that only 255 implicit consts exist within each abbrev table.
  u8 IMPLICIT_CONST_INDEX;
};

struct AbbreviationInfo
{
  /// Describes a table of `AbbreviationInfo`. Abbreviation codes increase monotonically and are 1-indexed
  /// as such a hash map is not required here; just perform arithmetic (-1) and look-up by index.
  using Table = std::vector<AbbreviationInfo>;
  // The abbreviation code
  u32 code;
  DwarfTag tag;
  bool has_children;
  bool is_declaration;
  std::vector<Abbreviation> attributes;
  std::vector<i64> implicit_consts;
  // TODO(simon): implement. These will be needed/useful when we resolve indirect/inter-DIE references. Ugh. DWARF.
  // More like, BARF, right?
  std::optional<std::tuple<int, Abbreviation>> find_abbreviation_indexed(Attribute name) const noexcept;
  std::optional<Abbreviation> find_abbreviation(Attribute name) const noexcept;
};

/*
 * Metadata that describes the memory layout of a particular DebugInfoEntry as well
 * as the abbreviation code and DWARF Tag. This type alone, does not mean anything, but can be considered
 * a key, by which we can lookup the actual DIE's data (it's attributes and attribute values), which is stored
 * in the UnitData container. This design saves more than 30% of memory that having the DIE's be constructed as a
 * prefix tree where each DIE would contain a pointer to it's parent, first child and first sibling (which is 8 * 3
 * bytes) as well as it's other data. That design also suffers from another problem; the die's aren't necessarily
 * laid out contiguously in-memory. This way we can keep all DieMetaData in a std::vector and do lookups for
 * parents, children, sibling, by using saying (address of this) + next_sibling for instance. The actual resolved
 * DIE data, will live in DebugInfoEntry. */
struct DieMetaData
{
  // .debug_info object file offset (absolute file offset)
  u64 section_offset : 37;
  u64 parent_id : 24;
  u64 die_data_offset : 3;
  u32 next_sibling : 31;
  bool has_children : 1;
  u16 abbreviation_code;
  DwarfTag tag;

  const DieMetaData *parent() const noexcept;
  const DieMetaData *sibling() const noexcept;
  const DieMetaData *children() const noexcept;
  bool is_super_scope_variable() const noexcept;

  // sets the parent's offset relative to this die in the vector containing all dies
  // thus, giving the ability to calculate parent by saying DebugInfoEntry* parent = (this - p_id);
  void set_parent_id(u64 p_id) noexcept;

  // sets the next sibling offset relative to this die in the vector containing all dies
  // thus, giving the ability to calculate next sibling by saying DebugInfoEntry* sib = (this + next_sibling);
  void set_sibling_id(u32 sib_id) noexcept;

  static DieMetaData create_die(u64 sec_offset, const AbbreviationInfo &abbr, u64 parent_id, u64 die_data_offset,
                                u64 next_sibling) noexcept;
};

class UnitHeader
{
public:
  UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data, u64 abbrev_offset,
             u8 addr_size, u8 format, DwarfVersion version, DwarfUnitType unit_type) noexcept;
  u8 offset_size() const noexcept;
  u8 addr_size() const noexcept;
  const u8 *abbreviation_data(const ElfSection *abbrev_sec) const noexcept;
  const u8 *data() const noexcept;
  const u8 *end_excl() const noexcept;
  u64 debug_info_offset() const noexcept;
  u8 format() const noexcept;
  u8 header_len() const noexcept;
  std::span<const u8> get_die_data() const noexcept;
  bool spans_across(u64 sec_offset) const noexcept;
  SymbolInfoId unit_id() const noexcept;
  DwarfVersion version() const noexcept;
  DwarfUnitType get_unit_type() const noexcept;

private:
  u64 sec_offset;
  u64 unit_size;
  std::span<const u8> die_data;
  u64 abbreviation_sec_offset;
  u8 address_size;
  u8 dwarf_format;
  DwarfVersion dw_version;
  DwarfUnitType unit_type;
  SymbolInfoId id;
};

// TODO(simon): ResolveAbbreviation
//  some abbreviations unfortunately, due to the infinite wisdom of the DWARF standard, have indirections. Save,
//  what, a few kb? Great? No. thus we will need a normal abbreviation set and a resolved one.
class ResolvedAbbreviationSet
{
public:
};

struct DieReference;

class UnitData
{
public:
  UnitData(ObjectFile *owning_objfile, UnitHeader header) noexcept;
  void set_abbreviations(AbbreviationInfo::Table &&table) noexcept;

  bool has_loaded_dies() const noexcept;
  const std::vector<DieMetaData> &get_dies() noexcept;
  void clear_die_metadata() noexcept;
  const AbbreviationInfo &get_abbreviation(u32 abbreviation_code) const noexcept;
  ObjectFile *get_objfile() const noexcept;
  /* TODO(simon): Resolve abbreviations which contains indirections to other abbreviations.*/
  ResolvedAbbreviationSet get_resolved_attributes(u64 abbreviation) noexcept;
  const UnitHeader &header() const noexcept;
  u64 section_offset() const noexcept;
  bool spans_across(u64 sec_offset) const noexcept;
  Index index_of(const DieMetaData *die) noexcept;
  std::span<const DieMetaData> continue_from(const DieMetaData *die) noexcept;
  const DieMetaData *get_die(u64 offset) noexcept;
  DieReference get_cu_die_ref(u64 offset) noexcept;
  DieReference get_cu_die_ref(Index offset) noexcept;

private:
  void load_dies() noexcept;
  ObjectFile *objfile;
  UnitHeader unit_header;
  // The Compilation unit die (i.e. the die with DW_TAG_compile_unit; also the first DIE found in `dies` - but as
  // that can be loaded/unloaded, the CU DIe also is a stand-alone die here)
  DieMetaData unit_die;
  std::vector<DieMetaData> dies;
  bool fully_loaded;
  AbbreviationInfo::Table abbreviations;
};

struct AddrRangeToCu
{
  AddressRange range;
  UnitData *data;
};

/** Interface to read, parse/resolve information described by a DWARF "debug information entry". It uses the DIE
 * metadata to find where in memory we need to read from together with what's found in UnitData to finally
 * understand that memory we read from. */
class DebugInfoEntry
{
public:
  DebugInfoEntry(DieMetaData *die, UnitData *data) noexcept;
  bool has_children() const noexcept;
  UnitData *get_cu_data() const noexcept;
  DieMetaData *get_die() const noexcept;

private:
  DieMetaData *die;
  UnitData *unit;
};

/* Creates a `UnitData` with it's abbreviations pre-processed and ready to be interpreted. */
UnitData *prepare_unit_data(ObjectFile *obj, const UnitHeader &header) noexcept;
std::vector<UnitHeader> read_unit_headers(ObjectFile *obj) noexcept;

struct DieReference
{
  UnitData *cu;
  const DieMetaData *die;
  bool valid() const noexcept;
  std::optional<AttributeValue> read_attribute(Attribute attr) noexcept;
};

struct IndexedDieReference
{
  UnitData *cu;
  Index die_index;

  bool valid() const noexcept;
};

} // namespace sym::dw