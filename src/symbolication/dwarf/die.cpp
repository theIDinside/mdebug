#include "die.h"
#include "debug_info_reader.h"
#include <string_view>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/enumerator.h>

extern bool DwarfLog;
namespace sym::dw {
const DieMetaData *
DieMetaData::parent() const noexcept
{
  if (parent_id == 0)
    return nullptr;
  return (this - parent_id);
}
const DieMetaData *
DieMetaData::sibling() const noexcept
{
  if (next_sibling == 0)
    return nullptr;
  return (this + next_sibling);
}

const DieMetaData *
DieMetaData::children() const noexcept
{
  if (!has_children)
    return nullptr;
  return this + 1;
}

bool
DieMetaData::is_super_scope_variable() const noexcept
{
  using enum DwarfTag;
  if (tag != DW_TAG_variable)
    return false;

  auto parent_die = parent();
  while (parent_die != nullptr) {
    switch (parent_die->tag) {
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
    parent_die = parent_die->parent();
  }
  return false;
}

void
DieMetaData::set_parent_id(u64 p_id) noexcept
{
  parent_id = p_id;
}

void
DieMetaData::set_sibling_id(u32 sib_id) noexcept
{
  next_sibling = sib_id;
}

/*static*/ DieMetaData
DieMetaData::create_die(u64 sec_offset, const AbbreviationInfo &abbr, u64 parent_id, u64 die_data_offset,
                        u64 next_sibling) noexcept
{
  return DieMetaData{.section_offset = sec_offset,
                     .parent_id = parent_id,
                     .die_data_offset = die_data_offset,
                     .next_sibling = static_cast<u32>(next_sibling),
                     .has_children = abbr.has_children,
                     .abbreviation_code = static_cast<u16>(abbr.code),
                     .tag = abbr.tag};
}

UnitHeader::UnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data,
                       u64 abbrev_offset, u8 addr_size, u8 format, DwarfVersion version,
                       DwarfUnitType unit_type) noexcept
    : sec_offset(sec_offset), unit_size(unit_size), die_data(die_data), abbreviation_sec_offset(abbrev_offset),
      address_size(addr_size), dwarf_format(format), dw_version(version), unit_type(unit_type), id(id)
{
}

u8
UnitHeader::offset_size() const noexcept
{
  return dwarf_format;
}

u8
UnitHeader::addr_size() const noexcept
{
  return address_size;
}

const u8 *
UnitHeader::abbreviation_data(const ElfSection *abbrev_sec) const noexcept
{
  ASSERT(abbrev_sec->get_name() == ".debug_abbrev",
         "Wrong ELF section was used, expected .debug_abbrev but received {}", abbrev_sec->get_name());
  return abbrev_sec->offset(abbreviation_sec_offset);
}

const u8 *
UnitHeader::data() const noexcept
{
  return die_data.data();
}

const u8 *
UnitHeader::end_excl() const noexcept
{
  return die_data.data() + die_data.size();
}

u64
UnitHeader::debug_info_offset() const noexcept
{
  return sec_offset;
}

u8
UnitHeader::format() const noexcept
{
  return dwarf_format;
}

u8
UnitHeader::header_len() const noexcept
{
  // if we're DWARF64, init length is 8 + 4 + 8, whereas DWARF32 contains 4 + 0 + 4
  switch (format()) {
  case 4:
    return (4 * 2) + 2 + 1 + (dw_version == DwarfVersion::D5 ? 1 : 0);
  case 8:
    return (8 * 2 + 4) + 2 + 1 + (dw_version == DwarfVersion::D5 ? 1 : 0);
  default:
    PANIC("Invalid Dwarf Format (32-bit / 64-bit)");
  }
}

std::span<const u8>
UnitHeader::get_die_data() const noexcept
{
  return die_data;
}

bool
UnitHeader::spans_across(u64 offset) const noexcept
{
  return offset >= sec_offset && offset <= (sec_offset + unit_size);
}

SymbolInfoId
UnitHeader::unit_id() const noexcept
{
  return id;
}

DwarfVersion
UnitHeader::version() const noexcept
{
  return dw_version;
}

DwarfUnitType
UnitHeader::get_unit_type() const noexcept
{
  return unit_type;
}

u64
UnitHeader::cu_size() const noexcept
{
  return unit_size;
}

UnitData::UnitData(ObjectFile *owning_objfile, UnitHeader header) noexcept
    : objfile(owning_objfile), unit_header(header), unit_die(), dies(), fully_loaded(false), loaded_die_count(0),
      abbreviations(), explicit_references(0), load_dies_mutex{}
{
}

void
UnitData::set_abbreviations(AbbreviationInfo::Table &&table) noexcept
{
  abbreviations = std::move(table);
}

const AbbreviationInfo &
UnitData::get_abbreviation(u32 abbreviation_code) const noexcept
{
  const auto adjusted = abbreviation_code - 1;
  ASSERT(adjusted < abbreviations.size(), "Abbreviation code was {} but we only have {}", abbreviation_code,
         abbreviations.size());
  return abbreviations[adjusted];
}

bool
UnitData::has_loaded_dies() const noexcept
{
  std::lock_guard lock(load_dies_mutex);
  return fully_loaded;
}

const std::vector<DieMetaData> &
UnitData::get_dies() noexcept
{
  load_dies();
  return dies;
}

void
UnitData::clear_die_metadata() noexcept
{
  release_reference();
  std::lock_guard lock(load_dies_mutex);
  if (explicit_references <= 0) {
    dies.clear();
    // actually release the memory. Otherwise, what's the point?
    dies.shrink_to_fit();
    fully_loaded = false;
  }
}

ObjectFile *
UnitData::get_objfile() const noexcept
{
  return objfile;
}

ResolvedAbbreviationSet
UnitData::get_resolved_attributes(u64) noexcept
{
  TODO("ResolvedAbbreviationSet UnitData::get_resolved_attributes({}), not yet implemented. "
       "ResolvedAbbreviationSet not yet implemented either.");
}

const UnitHeader &
UnitData::header() const noexcept
{
  return unit_header;
}

u64
UnitData::section_offset() const noexcept
{
  return header().debug_info_offset();
}

bool
UnitData::spans_across(u64 offset) const noexcept
{
  return header().spans_across(offset);
}

Index
UnitData::index_of(const DieMetaData *die) noexcept
{
  ASSERT(die != nullptr && !dies.empty(), "You passed a nullptr or DIE's for this unit has not been loaded");
  auto begin = dies.data();
  DBG(auto end = dies.data() + dies.size());
  ASSERT(die >= begin && die < end, "die does not belong to this CU or the dies has been unloaded!");
  return Index{static_cast<u32>(die - begin)};
}

std::span<const DieMetaData>
UnitData::continue_from(const DieMetaData *die) noexcept
{
  const auto index = index_of(die);
  return std::span{dies.begin() + index, dies.end()};
}

const DieMetaData *
UnitData::get_die(u64 offset) noexcept
{
  load_dies();
  auto it = std::ranges::find_if(dies, [&](const dw::DieMetaData &die) { return die.section_offset == offset; });
  if (it == std::end(dies))
    return nullptr;
  return &(*it);
}

DieReference
UnitData::get_cu_die_ref(u64 offset) noexcept
{
  return DieReference{this, get_die(offset)};
}

DieReference
UnitData::get_cu_die_ref(Index offset) noexcept
{
  return DieReference{this, &get_dies()[offset.value()]};
}

void
UnitData::take_reference() noexcept
{
  std::lock_guard lock(load_dies_mutex);
  explicit_references += 1;
}

void
UnitData::release_reference() noexcept
{
  ASSERT(explicit_references > 0, "Explicitly taken references can not be 0 when we release a reference.");
  std::lock_guard lock(load_dies_mutex);
  explicit_references -= 1;
}

static constexpr auto
guess_die_count(auto unit_size) noexcept
{
  return unit_size / 24;
}

void
UnitData::load_dies() noexcept
{
  std::lock_guard lock(load_dies_mutex);
  if (fully_loaded)
    return;
  fully_loaded = true;
  UnitReader reader{this};

  const auto die_sec_offset = reader.sec_offset();
  const auto [abbr_code, uleb_sz] = reader.read_uleb128();

  ASSERT(abbr_code <= abbreviations.size() && abbr_code != 0,
         "[cu=0x{:x}]: Unit DIE abbreviation code {} is invalid, max={}", section_offset(), abbr_code,
         abbreviations.size());
  auto &abbreviation = abbreviations[abbr_code - 1];
  reader.skip_attributes(abbreviation.attributes);
  // Siblings and parent ids stored here
  std::vector<int> parent_node;
  std::vector<int> sibling_node;
  parent_node.push_back(0);
  sibling_node.push_back(0);
  unit_die = DieMetaData::create_die(die_sec_offset, abbreviation, NONE_INDEX, uleb_sz, NONE_INDEX);
  ASSERT(dies.empty(), "Expected dies to be empty, but wasn't! (cu=0x{:x})", section_offset());
  dies.reserve(guess_die_count(header().cu_size()));
  dies.push_back(unit_die);
  bool new_level = true;
  while (reader.has_more()) {
    const auto die_sec_offset = reader.sec_offset();
    const auto [abbr_code, uleb_sz] = reader.read_uleb128();
    ASSERT(abbr_code <= abbreviations.size(), "Abbreviation code {} is invalid. Dies processed={}", abbr_code,
           dies.size());
    if (abbr_code == 0) {
      if (parent_node.empty())
        break;
      new_level = false;
      parent_node.pop_back();
      sibling_node.pop_back();
      continue;
    }

    if (!new_level) {
      dies[sibling_node.back()].set_sibling_id(dies.size() - sibling_node.back());
      sibling_node.back() = dies.size();
    } else {
      sibling_node.push_back(dies.size());
    }

    auto &abbreviation = abbreviations[abbr_code - 1];
    auto new_entry = DieMetaData::create_die(die_sec_offset, abbreviation, dies.size() - parent_node.back(),
                                             uleb_sz, NONE_INDEX);

    reader.skip_attributes(abbreviation.attributes);
    new_level = abbreviation.has_children;
    if (new_level) {
      parent_node.push_back(dies.size());
    }

    dies.push_back(new_entry);
  }
  loaded_die_count = dies.size();
}

UnitData *
prepare_unit_data(ObjectFile *obj, const UnitHeader &header) noexcept
{
  const auto abbrev_sec = obj->parsed_elf->debug_abbrev;

  AbbreviationInfo::Table result{};
  const u8 *abbr_ptr = header.abbreviation_data(abbrev_sec);
  while (true) {
    AbbreviationInfo info;
    info.is_declaration = false;
    abbr_ptr = decode_uleb128(abbr_ptr, info.code);

    // we've reached the end of this abbrev sub-section.
    if (info.code == 0) {
      break;
    }

    abbr_ptr = decode_uleb128(abbr_ptr, info.tag);
    info.has_children = *abbr_ptr;
    abbr_ptr++;

    // read declarations
    for (;;) {
      Abbreviation abbr;
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.name);
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.form);
      if (abbr.name == Attribute::DW_AT_declaration) {
        if (!info.is_declaration) {
          info.is_declaration = true;
        }
      }

      if (abbr.form == AttributeForm::DW_FORM_implicit_const) {
        ASSERT((u8)info.implicit_consts.size() != UINT8_MAX, "Maxed out IMPLICIT const entries!");
        abbr.IMPLICIT_CONST_INDEX = info.implicit_consts.size();
        info.implicit_consts.push_back(0);
        abbr_ptr = decode_leb128(abbr_ptr, info.implicit_consts.back());
      } else {
        abbr.IMPLICIT_CONST_INDEX = -1;
      }
      if (std::to_underlying(abbr.name) == 0) {
        break;
      }
      info.attributes.push_back(abbr);
    }
    result.push_back(info);
  }
  auto dwarf_unit_data = new UnitData{obj, header};
  dwarf_unit_data->set_abbreviations(std::move(result));

  return dwarf_unit_data;
}

std::vector<UnitHeader>
read_unit_headers(ObjectFile *obj) noexcept
{
  if (DwarfLog) {
    LOG("dwarf", "Reading {} obfile compilation unit headers", obj->path.c_str());
  }
  const auto dbg_info = obj->parsed_elf->debug_info;
  std::vector<UnitHeader> result{};
  DwarfBinaryReader reader{obj->parsed_elf, dbg_info};
  auto unit_index = 0u;
  while (reader.has_more()) {
    const auto sec_offset = reader.bytes_read();
    u64 unit_len = reader.peek_value<u32>();
    u8 format = 4u;
    auto init_len = 4;
    if ((unit_len & 0xff'ff'ff'ff) == 0xff'ff'ff'ff) {
      reader.skip(4);
      unit_len = reader.read_value<u64>();
      format = 8;
      init_len = 12;
    } else {
      reader.skip(4);
    }
    const auto total_unit_size = unit_len + init_len;
    reader.bookmark();
    const auto version = reader.read_value<u16>();
    auto unit_type = DwarfUnitType::DW_UT_compile;
    u8 addr_size = 8;
    if (version == 5) {
      unit_type = reader.read_value<DwarfUnitType>();
      addr_size = reader.read_value<u8>();
    }

    u64 abb_offs = 0u;
    switch (format) {
    case 4:
      abb_offs = reader.read_value<u32>();
      break;
    case 8:
      abb_offs = reader.read_value<u64>();
      break;
    }

    if (version < 5) {
      addr_size = reader.read_value<u8>();
    }
    const auto header_len = reader.pop_bookmark();
    const auto die_data_len = unit_len - header_len;
    UnitHeader h{SymbolInfoId{unit_index},
                 sec_offset,
                 total_unit_size,
                 reader.get_span(die_data_len),
                 abb_offs,
                 addr_size,
                 format,
                 (DwarfVersion)version,
                 unit_type};
    result.push_back(h);
    ++unit_index;
    ASSERT(reader.bytes_read() == sec_offset + unit_len + init_len,
           "Well, this is wrong. Expected to have read {} bytes, but was at {}", sec_offset + unit_len + init_len,
           reader.bytes_read());
  }
  if (DwarfLog)
    LOG("dwarf", "Read {} compilation unit headers", result.size());
  return result;
}

bool
DieReference::valid() const noexcept
{
  return cu != nullptr && die != nullptr;
}

bool
IndexedDieReference::valid() const noexcept
{
  return cu != nullptr;
}

IndexedDieReference
DieReference::as_indexed() const noexcept
{
  return IndexedDieReference{.cu = cu, .die_index = cu->index_of(die)};
}

std::optional<AttributeValue>
DieReference::read_attribute(Attribute attr) const noexcept
{
  UnitReader reader{cu};
  const auto &attrs = cu->get_abbreviation(die->abbreviation_code);
  reader.seek_die(*die);
  for (auto attribute : attrs.attributes) {
    const auto value = read_attribute_value(reader, attribute, attrs.implicit_consts);
    if (value.name == attr) {
      return value;
    }
  }
  return std::nullopt;
}

const DieMetaData *
IndexedDieReference::get_die() noexcept
{
  return &cu->get_dies()[die_index.value()];
}
} // namespace sym::dw