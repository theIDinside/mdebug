/** LICENSE TEMPLATE */
#pragma once
#include "die_ref.h"
#include "symbolication/cu_symbol_info.h"
#include "unit_header.h"
#include <common.h>
#include <limits>
#include <mutex>
#include <symbolication/block.h>
#include <symbolication/dwarf.h>
#include <utils/indexing.h>

class ObjectFile;
struct ElfSection;

void SetDwarfLogConfig(bool value) noexcept;

namespace sym::dw {

bool IsCompileUnit(DwarfUnitType type);

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
  bool HasChildren : 1;
  bool IsDeclaration : 1;
  // Whether or not this abbreviation represents an addressable Debug Information Entry
  // One may wonder why it's not sufficient to check if tag == DW_TAG_subprogram etc; well, thanks to referenceing
  // DIE's we're f'ed. Not all subprogram dies have address. They are instead often found on DIE's that reference
  // another subprogram die and have the abstract_origin attribute or specification attribute.
  // Therefore, when we load the abbreviations, we scan if the abbreviation set contained a "PC-like" attribute, like
  // DW_AT_low_pc, DW_AT_high_pc, DW_AT_ranges or DW_AT_entry
  bool IsAddressable : 1;
  bool AbstractOrigin : 1;
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

template <DwarfTag... tags>
constexpr bool
maybe_null_any_of(const DieMetaData *die)
{
  if (die == nullptr) {
    return false;
  }
  return ((die->tag == tags) || ...);
}

class DieReference;

class UnitData
{
public:
  UnitData(ObjectFile *owning_objfile, UnitHeader header) noexcept;

  /**
   * Construct UnitData object and initialize it. Initialization involves reading the unit die
   * and (possibly) reading build directory and unit name, if the unit is of COMPILE_TYPE or PARTIAL_TYPE (i.e. a
   * compilation unit of some sort.)
   */
  static UnitData *CreateInitUnitData(ObjectFile *owningObject, UnitHeader header,
                                      AbbreviationInfo::Table &&abbreviations) noexcept;
  bool IsCompilationUnitLike() const noexcept;

  void set_abbreviations(AbbreviationInfo::Table &&table) noexcept;

  bool has_loaded_dies() const noexcept;
  const std::vector<DieMetaData> &get_dies() noexcept;
  void ClearLoadedCache() noexcept;
  const AbbreviationInfo &get_abbreviation(u32 abbreviation_code) const noexcept;
  ObjectFile *GetObjectFile() const noexcept;
  const UnitHeader &header() const noexcept;
  /// The offset from the beginning of the ELF section called .debug_info to this compilation unit.
  u64 SectionOffset() const noexcept;
  /// Size (bytes) of this compilation unit in the .debug_info ELF section
  u64 UnitSize() const noexcept;
  bool spans_across(u64 sec_offset) const noexcept;
  u64 index_of(const DieMetaData *die) noexcept;
  std::span<const DieMetaData> continue_from(const DieMetaData *die) noexcept;

  const char* GetBuildDirectory() const noexcept;
  const DieMetaData *GetDebugInfoEntry(u64 offset) noexcept;
  DieReference GetDieReferenceByOffset(u64 offset) noexcept;
  DieReference GetDieByCacheIndex(u64 index) noexcept;
  std::optional<u32> StrOffsetBase() noexcept;
  u32 RangeListBase() noexcept;
  u32 AddressBase() noexcept;

  constexpr bool
  LineNumberOffsetKnown() const noexcept
  {
    return mStatementListOffset != std::numeric_limits<u64>::max();
  }
  constexpr bool
  HasBuildDirectory() const noexcept
  {
    return mBuildDirectory != nullptr;
  }

private:
  void LoadDieMetadata() noexcept;
  ObjectFile *mObjectFile;
  UnitHeader mUnitHeader;
  // The Compilation unit die (i.e. the die with DW_TAG_compile_unit; also the first DIE found in `dies` - but as
  // that can be loaded/unloaded, the CU DIe also is a stand-alone die here)
  DieMetaData mUnitDie;
  std::vector<DieMetaData> mDieCollection;
  bool mFullyLoaded;
  u32 mLoadedDiesCount;
  AbbreviationInfo::Table mAbbreviation;
  std::optional<u32> mStringOffset{};
  std::optional<u32> mRngListOffset{};
  std::optional<u32> mAddrOffset{};
  mutable std::mutex mLoadDiesMutex;
  const char *mBuildDirectory{nullptr};
  u64 mStatementListOffset{std::numeric_limits<u64>::max()};
};

/* Creates a `UnitData` with it's abbreviations pre-processed and ready to be interpreted. */
UnitData *prepare_unit_data(ObjectFile *obj, const UnitHeader &header) noexcept;

class UnitHeadersRead {
  u64 mTotalSize;
  u64 mMaxUnitSize;
  std::vector<UnitHeader> mUnitHeaders;
  void Accumulate(u64 unitSize) noexcept;
  u64 AverageUnitSize() noexcept;
  void AddUnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data, u64 abbrev_offset, u8 addr_size, u8 format, DwarfVersion version, DwarfUnitType unit_type) noexcept;
  void AddTypeUnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data, u64 abbrev_offset, u8 addr_size, u8 format, u64 type_signature, u64 type_offset) noexcept;
public:
  void ReadUnitHeaders(ObjectFile *obj) noexcept;
  std::span<UnitHeader> Headers() noexcept;
};

} // namespace sym::dw

namespace fmt {
template <> struct formatter<sym::dw::UnitData>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::dw::UnitData &cu, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "CompilationUnit {{ cu=0x{:x} }}", cu.SectionOffset());
  }
};

template <> struct formatter<sym::dw::DieReference>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::dw::DieReference &ref, FormatContext &ctx) const
  {
    if (auto cu = ref.GetUnitData(); cu != nullptr) {
      if (ref.GetUnitData()->has_loaded_dies()) {
        auto die = ref.GetDie();
        ASSERT(die, "die was null!");
        return fmt::format_to(ctx.out(), "DieRef {{ cu=0x{:x}, die=0x{:x} ({}) }}", cu->SectionOffset(),
                              die->section_offset, to_str(die->tag));
      } else {
        return fmt::format_to(ctx.out(), "DieRef {{ cu=0x{:x} (dies not loaded) }}", cu->SectionOffset());
      }
    }
    return fmt::format_to(ctx.out(), "DieRef {{ ??? }}");
  }
};

template <> struct formatter<sym::dw::IndexedDieReference>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::dw::IndexedDieReference &ref, FormatContext &ctx) const
  {
    if (ref.GetUnitData()) {
      return fmt::format_to(ctx.out(), "IndexedDieRef {{ cu=0x{:x}, die #{} }}",
                            ref.GetUnitData()->SectionOffset(), ref.GetIndex());
    }
    return fmt::format_to(ctx.out(), "IndexedDieRef {{ ??? }}");
  }
};

} // namespace fmt