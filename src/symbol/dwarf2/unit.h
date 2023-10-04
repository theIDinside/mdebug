#pragma once
#include "die.h"
#include "symbol/dwarf/dwarf_defs.h"
#include "symbol/dwarf2/dwarf_common.h"
#include "utils/worker_task.h"
#include <common.h>
#include <span>

struct TraceeController;

namespace sym {
struct ObjectFile;
struct ElfSection;
class Elf;
} // namespace sym

namespace sym::dw2 {

struct DebugInfoEntry;
class ResolvedAbbreviationSet;

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
  u32 sibling_offset;
  std::vector<Abbreviation> attributes;
  std::vector<i64> implicit_consts;
  std::optional<std::tuple<int, Abbreviation>> find_abbreviation_indexed(Attribute name) const noexcept;
  std::optional<Abbreviation> find_abbreviation(Attribute name) const noexcept;
};

#define ATTR_CTOR(DataType, field)                                                                                \
  constexpr AttributeValue(DataType data, AttributeForm form, Attribute name) noexcept                            \
      : form{form}, name{name}, value{data}                                                                       \
  {                                                                                                               \
  }

template <typename T>
concept AttributeValueType = std::is_same_v<T, u64> || std::is_same_v<T, i64> || std::is_same_v<T, DataBlock> ||
                             std::is_same_v<T, std::string_view> || std::is_same_v<T, UnrelocatedTraceePointer>;

/** Fully-formed attribtue */
struct AttributeValue
{
  template <AttributeValueType T>
  constexpr AttributeValue(T value, AttributeForm form, Attribute name) noexcept
      : form{form}, name{name}, value{value}
  {
  }

  std::uintptr_t address() const noexcept;
  std::string_view string() const noexcept;
  DataBlock block() const noexcept;
  u64 unsigned_value() const noexcept;
  i64 signed_value() const noexcept;
  AttributeForm form;
  Attribute name;

private:
  union _value
  { // Size = 16 bytes
    constexpr _value(std::string_view str) noexcept : str{str} {}
    constexpr _value(DataBlock block) noexcept : block(block) {}
    constexpr _value(u64 u) noexcept : u(u) {}
    constexpr _value(i64 i) noexcept : i(i) {}
    constexpr _value(UnrelocatedTraceePointer ptr) noexcept : addr(ptr) {}

    DataBlock block;
    std::string_view str;
    u64 u;
    i64 i;
    UnrelocatedTraceePointer addr;
  } value;
};

struct DwarfUnitHeader : public DwarfId
{
public:
  DwarfUnitHeader(u64 sec_offset, std::span<const u8> die_data, u64 abbrev_offset, u8 addr_size, u8 format,
                  DwarfVersion version, DwarfUnitType unit_type) noexcept;
  u8 offset_size() const noexcept;
  u8 addr_size() const noexcept;
  const u8 *abbreviation_data(const ElfSection *abbrev_sec) const noexcept;

  const u8 *data() const noexcept;
  const u8 *end_excl() const noexcept;
  u64 debug_info_offset() const noexcept;
  u8 format() const noexcept;
  u8 header_len() noexcept;

private:
  std::span<const u8> m_die_data;
  u64 m_abbrev_offset;
  u8 m_addr_size;
  u8 m_format;
  DwarfVersion m_version;
  DwarfUnitType m_unit_type;
};

class UnitReader;

class DwarfUnitData : public DwarfId
{
public:
  friend class UnitReader;
  DwarfUnitData(ObjectFile *obj, DwarfUnitHeader header) noexcept;
  // initialize & load operations
  void set_abbrev(AbbreviationInfo::Table &&table) noexcept;
  void load_dies() noexcept;

  // Query operations
  u64 debug_info_offset() const noexcept;
  bool dies_read() const noexcept;
  void clear_die_metadata();
  const std::vector<DebugInfoEntry> &dies() const noexcept;
  const AbbreviationInfo &get_abbreviation_set(u32 abbrev_code) const noexcept;
  ObjectFile *get_objfile() const noexcept;
  const u8 *die_data(const DebugInfoEntry &entry) noexcept;
  DebugInfoEntry *get_die(DwarfId offset) noexcept;
  ResolvedAbbreviationSet get_resolved_attributes(u64 code) noexcept;

private:
  ObjectFile *p_obj;
  DwarfUnitHeader m_header;
  DebugInfoEntry m_unit_die;
  // DIE meta data: contains the TAG for the individual DIE's as well as the relationship descriptors.
  std::vector<DebugInfoEntry> m_dies;
  bool all_dies_loaded;
  AbbreviationInfo::Table m_abbrev_table;
};

class UnitReader
{
public:
  explicit UnitReader(DwarfUnitData *unit_data) noexcept;
  explicit UnitReader(DwarfUnitData *unit_data, const DebugInfoEntry *entry) noexcept;
  explicit UnitReader(const UnitReader &reader) noexcept = default;
  UnitReader &operator=(const UnitReader &reader) noexcept = default;

  // skips the attribute encodings in buffer. The amount of bytes skipped is determined by the understanding of how
  // (name + form) is represented in the DWARF data. Takes a `span` as it's a cheap copy view of the actual parsed
  // abbreviation data (thus we don't need to copy a subrange of std::vector into a new std::vector)
  void skip_attributes(const std::span<const Abbreviation> &attributes) noexcept;
  UnrelocatedTraceePointer read_address() noexcept;
  std::string_view read_string() noexcept;
  DataBlock read_block(u64 size) noexcept;
  u64 bytes_read() const noexcept;

  /// Needs to be auto, otherwise we are not widening the value
  template <std::integral Integral>
  constexpr auto
  read_integral() noexcept
  {
    Integral type = *(Integral *)current_ptr;
    current_ptr += sizeof(Integral);
    if constexpr (std::unsigned_integral<Integral>) {
      return static_cast<u64>(type);
    } else if constexpr (std::signed_integral<Integral>) {
      return static_cast<i64>(type);
    } else {
      static_assert(always_false<Integral>,
                    "Somehow, some way, an integral slipped through that's neither signed nor unsigned");
    }
  }

  void set_die(const DebugInfoEntry &entry) noexcept;

  u64 uleb128() noexcept;
  i64 leb128() noexcept;
  // decodes LEB128 and saves how many bytes were read, into out parameter `bytes_read`
  u64 uleb128_count_read(u8 &bytes_read) noexcept;
  i64 leb128_count_read(u8 &bytes_read) noexcept;
  u64 read_offset() noexcept;
  bool has_more() const noexcept;
  u64 read_section_offset(u64 offset) const noexcept;
  u64 read_bytes(u8 bytes) noexcept;
  UnrelocatedTraceePointer read_by_idx_from_addr_table(u64 address_index,
                                                       std::optional<u64> addr_table_base) const noexcept;
  std::string_view read_by_idx_from_str_table(u64 str_index, std::optional<u64> str_offsets_base) const noexcept;
  u64 read_by_idx_from_rnglist(u64 range_index, std::optional<u64> rng_list_base) const noexcept;
  u64 read_loclist_index(u64 range_index, std::optional<u64> loc_list_base) const noexcept;
  u64 sec_offset() const noexcept;
  const ObjectFile *objfile() const;
  const Elf *elf() const;
  const u8 *ptr() noexcept;

private:
  DwarfUnitData *unit_data;
  const u8 *current_ptr;
};

struct DIEResult
{
  DwarfUnitData *data;
  // one uses data_key to access where it actually lives, inside data
  DebugInfoEntry *data_key;
};

struct ResolvedAttribute
{
  DwarfUnitData *m_cu;
  u64 m_die_offset : 63;
  bool value_loaded : 1;
  AttributeValue value;
};

class ResolvedAbbreviationSet
{
public:
  ResolvedAbbreviationSet() = default;

private:
  /// Describes a table of `AbbreviationInfo`. Abbreviation codes increase monotonically and are 1-indexed
  /// as such a hash map is not required here; just perform arithmetic (-1) and look-up by index.
  using Table = std::vector<AbbreviationInfo>;
  // The abbreviation code
  u32 code;
  DwarfTag tag;
  bool has_children;
  std::vector<i64> implicit_consts;
  std::optional<ResolvedAttribute> find_abbreviation(Attribute name) const noexcept;
  std::vector<ResolvedAttribute> m_attributes;
};

// reads data from .debug_abbrev and creates the per-compilation unit data for the CU represented by `header`
DwarfUnitData *prepare_unit_data(ObjectFile *obj_file, const DwarfUnitHeader &header) noexcept;

std::vector<DwarfUnitHeader> read_cu_headers(ObjectFile *obj) noexcept;

class DwarfUnitDataTask : public utils::Task
{
public:
  using Work = std::span<DwarfUnitHeader>;
  DwarfUnitDataTask(ObjectFile *obj, Work cus) noexcept;
  virtual ~DwarfUnitDataTask() noexcept;
  void execute_task() noexcept override;
  static std::vector<DwarfUnitDataTask *> create_work(ObjectFile *obj, Work work) noexcept;

private:
  ObjectFile *p_obj;
  Work m_cu_headers;
};

AttributeValue read_attribute_value(UnitReader &reader, Abbreviation abbr,
                                    std::vector<i64> &implicit_consts) noexcept;

} // namespace sym::dw2