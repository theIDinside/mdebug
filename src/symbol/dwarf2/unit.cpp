#include "unit.h"
#include "../elf.h"
#include "../objfile.h"
#include "symbol/dwarf/dwarf_defs.h"
#include "symbol/dwarf2/die.h"
#include <algorithm>
#include <stack>
#include <utils/thread_pool.h>

namespace sym::dw2 {

std::optional<std::tuple<int, Abbreviation>>
AbbreviationInfo::find_abbreviation_indexed(Attribute name) const noexcept
{
  auto idx = 0;
  for (const auto &abb : this->attributes) {
    if (abb.name == name)
      return std::make_tuple(idx, abb);
    ++idx;
  }
  return std::nullopt;
}

std::optional<Abbreviation>
AbbreviationInfo::find_abbreviation(Attribute name) const noexcept
{
  for (const auto &abb : this->attributes) {
    if (abb.name == name)
      return abb;
  }
  return std::nullopt;
}

std::uintptr_t
AttributeValue::address() const noexcept
{
  return value.addr;
}
std::string_view
AttributeValue::string() const noexcept
{
  return value.str;
}
DataBlock
AttributeValue::block() const noexcept
{
  return value.block;
}
u64
AttributeValue::unsigned_value() const noexcept
{
  return value.u;
}
i64
AttributeValue::signed_value() const noexcept
{
  return value.i;
}

const ObjectFile *
UnitReader::objfile() const
{
  return unit_data->get_objfile();
}

const Elf *
UnitReader::elf() const
{
  return objfile()->elf();
}

const u8 *
UnitReader::ptr() noexcept
{
  return current_ptr;
}

AttributeValue
read_attribute_value(UnitReader &reader, Abbreviation abbr, std::vector<i64> &implicit_consts) noexcept
{
  static constexpr auto IS_DWZ = false;
  ASSERT(IS_DWZ == false, ".dwo files not supported yet");
  if (abbr.IMPLICIT_CONST_INDEX != UINT8_MAX) {
    return AttributeValue{implicit_consts[abbr.IMPLICIT_CONST_INDEX], AttributeForm::DW_FORM_implicit_const,
                          abbr.name};
  }

  const auto elf = reader.elf();

  switch (abbr.form) {
  case AttributeForm::DW_FORM_ref_addr:
    return AttributeValue{reader.read_offset(), abbr.form, abbr.name};
    break;
  case AttributeForm::DW_FORM_addr: {
    return AttributeValue{reader.read_address(), abbr.form, abbr.name};
  }
  case AttributeForm::Reserved:
    PANIC("Can't handle RESERVED");
  case AttributeForm::DW_FORM_block2:
    return AttributeValue{reader.read_block(2), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_block4:
    return AttributeValue{reader.read_block(4), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data2:
    return AttributeValue{reader.read_integral<u16>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data4:
    return AttributeValue{reader.read_integral<u32>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data8:
    return AttributeValue{reader.read_integral<u64>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data16:
    return AttributeValue{reader.read_block(16), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_string:
    return AttributeValue{reader.read_string(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_exprloc:
    [[fallthrough]];
  case AttributeForm::DW_FORM_block: {
    const auto size = reader.uleb128();
    return AttributeValue{reader.read_block(size), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_block1: {
    const auto size = reader.read_integral<u8>();
    return AttributeValue{reader.read_block(size), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_data1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_flag:
    return AttributeValue{reader.read_integral<u8>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_sdata:
    return AttributeValue{reader.leb128(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_strp: {
    ASSERT(elf->debug_str != nullptr, ".debug_str expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.read_offset();
      std::string_view indirect_str{(const char *)elf->debug_str->begin() + offset};
      return AttributeValue{indirect_str, abbr.form, abbr.name};
    }
  }
  case AttributeForm::DW_FORM_line_strp: {
    ASSERT(elf->debug_line_str != nullptr, ".debug_line expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.read_offset();
      const auto ptr = elf->debug_line_str->begin() + offset;
      const std::string_view indirect_str{(const char *)ptr};
      return AttributeValue{indirect_str, abbr.form, abbr.name};
    }
  }
  case AttributeForm::DW_FORM_udata:
    return AttributeValue{reader.uleb128(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_ref1: {
    const auto offset = reader.read_integral<u8>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref2: {
    const auto offset = reader.read_integral<u16>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref4: {
    const auto offset = reader.read_integral<u32>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref8: {
    const auto offset = reader.read_integral<u64>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_udata: {
    const auto offset = reader.uleb128();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_indirect: {
    const auto new_form = (AttributeForm)reader.uleb128();
    Abbreviation new_abbr{.name = abbr.name, .form = new_form, .IMPLICIT_CONST_INDEX = UINT8_MAX};
    if (new_form == AttributeForm::DW_FORM_implicit_const) {
      const auto value = reader.leb128();
      new_abbr.IMPLICIT_CONST_INDEX = implicit_consts.size();
      implicit_consts.push_back(value);
    }
    return read_attribute_value(reader, new_abbr, implicit_consts);
  }
  case AttributeForm::DW_FORM_sec_offset: {
    const auto offset = reader.read_offset();
    return AttributeValue{offset, abbr.form, abbr.name};
  }

  case AttributeForm::DW_FORM_flag_present:
    return AttributeValue{(u64) true, abbr.form, abbr.name};
  // fall through. Nasty attribute forms; beware
  case AttributeForm::DW_FORM_strx1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx2:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx3:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx4: {
    const auto base = std::to_underlying(AttributeForm::DW_FORM_strx1) - 1;
    const auto bytes_to_read = std::to_underlying(abbr.form) - base;
    const auto idx = reader.read_bytes(bytes_to_read);
    return AttributeValue{reader.read_by_idx_from_str_table(idx, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_strx: {
    const auto idx = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_str_table(idx, {}), abbr.form, abbr.name};
  }

  // fall through. Nasty attribute forms; beware
  case AttributeForm::DW_FORM_addrx1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx2:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx3:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx4: {
    ASSERT(elf->debug_addr != nullptr, ".debug_addr not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto base = std::to_underlying(AttributeForm::DW_FORM_addrx1) - 1;
    const auto bytes_to_read = std::to_underlying(abbr.form) - base;
    const auto addr_index = reader.read_bytes(bytes_to_read);
    return AttributeValue{reader.read_by_idx_from_addr_table(addr_index, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_addrx: {
    ASSERT(elf->debug_addr != nullptr, ".debug_addr not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto addr_table_index = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_addr_table(addr_table_index, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_sup4:
    PANIC("Unsupported attribute form DW_FORM_ref_sup4");
  case AttributeForm::DW_FORM_strp_sup:
    PANIC("Unsupported attribute form DW_FORM_strp_sup");
  case AttributeForm::DW_FORM_ref_sig8:
    PANIC("Unsupported attribute form DW_FORM_ref_sig8");
  case AttributeForm::DW_FORM_implicit_const:
    ASSERT(abbr.IMPLICIT_CONST_INDEX != UINT8_MAX, "Invalid implicit const index");
    return AttributeValue{implicit_consts[abbr.IMPLICIT_CONST_INDEX], abbr.form, abbr.name};
  case AttributeForm::DW_FORM_loclistx: {
    ASSERT(elf->debug_loclist != nullptr, ".debug_rnglists not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto idx = reader.uleb128();
    return AttributeValue{reader.read_loclist_index(idx, {}), abbr.form, abbr.name};
  }

  case AttributeForm::DW_FORM_rnglistx: {
    ASSERT(elf->debug_rnglists != nullptr, ".debug_rnglists not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto addr_table_index = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_rnglist(addr_table_index, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_sup8:
    PANIC("Unsupported attribute form DW_FORM_ref_sup8");
    break;
  }
  PANIC("Unknown Attribute Form");
}

DwarfUnitHeader::DwarfUnitHeader(u64 sec_offset, std::span<const u8> die_data, u64 abbrev_offset, u8 addr_size,
                                 u8 format, DwarfVersion version, DwarfUnitType unit_type) noexcept
    : DwarfId(sec_offset), m_die_data(die_data), m_abbrev_offset(abbrev_offset), m_addr_size(addr_size),
      m_format(format), m_version(version), m_unit_type(unit_type)
{
}

const u8 *
DwarfUnitHeader::data() const noexcept
{
  return m_die_data.data();
}

const u8 *
DwarfUnitHeader::end_excl() const noexcept
{
  return m_die_data.data() + m_die_data.size();
}

u64
DwarfUnitHeader::debug_info_offset() const noexcept
{
  return get_id();
}

u8
DwarfUnitHeader::offset_size() const noexcept
{
  return m_format;
}

u8
DwarfUnitHeader::addr_size() const noexcept
{
  return m_addr_size;
}

const u8 *
DwarfUnitHeader::abbreviation_data(const ElfSection *abbrev_sec) const noexcept
{
  ASSERT(abbrev_sec->get_name() == ".debug_abbrev", "You passed the wrong ELF Section");
  return abbrev_sec->offset(m_abbrev_offset);
}

u8
DwarfUnitHeader::format() const noexcept
{
  return m_format;
}

u8
DwarfUnitHeader::header_len() noexcept
{
  // if we're DWARF64, init length is 8 + 4 + 8, whereas DWARF32 contains 4 + 0 + 4
  switch (format()) {
  case 4:
    return (4 * 2) + 2 + 1 + (m_version == DwarfVersion::D5 ? 1 : 0);
  case 8:
    return (8 * 2 + 4) + 2 + 1 + (m_version == DwarfVersion::D5 ? 1 : 0);
  default:
    PANIC("Invalid Dwarf Format (32-bit / 64-bit)");
  }
}

DwarfUnitData::DwarfUnitData(ObjectFile *obj, DwarfUnitHeader header) noexcept
    : DwarfId(header.get_id()), p_obj(obj), m_header(header), m_unit_die(), m_dies(), m_abbrev_table()
{
}

u64
DwarfUnitData::debug_info_offset() const noexcept
{
  return get_id();
}

bool
DwarfUnitData::dies_read() const noexcept
{
  return !m_dies.empty();
}

void
DwarfUnitData::clear_die_metadata()
{
  m_dies.clear();
}

const std::vector<DebugInfoEntry> &
DwarfUnitData::dies() const noexcept
{
  return m_dies;
}

const AbbreviationInfo &
DwarfUnitData::get_abbreviation_set(u32 abbrev_code) const noexcept
{
  ASSERT(!m_abbrev_table.empty() && (abbrev_code - 1) < m_abbrev_table.size(), "Abbrev code not found in table");
  return m_abbrev_table[abbrev_code - 1];
}

ObjectFile *
DwarfUnitData::get_objfile() const noexcept
{
  return p_obj;
}

const u8 *
DwarfUnitData::die_data(const DebugInfoEntry &entry) noexcept
{
  return p_obj->elf()->debug_info->offset(entry.sec_offset + entry.die_data_offset);
}

DebugInfoEntry *
DwarfUnitData::get_die(DwarfId offset) noexcept
{
  auto it = std::lower_bound(m_dies.begin(), m_dies.end(), offset, [](DebugInfoEntry &entry, DwarfId offset) {
    return entry.sec_offset < offset.get_id();
  });
  ASSERT(it->sec_offset == offset.get_id(), "Expected to find die 0x{:x} but found 0x{:x}", offset.get_id(),
         u64{it->sec_offset});
  return it.base();
}

ResolvedAbbreviationSet
DwarfUnitData::get_resolved_attributes(u64 code) noexcept
{
}

void
DwarfUnitData::set_abbrev(AbbreviationInfo::Table &&table) noexcept
{
  m_abbrev_table = std::move(table);
}

void
UnitReader::skip_attributes(const std::span<const Abbreviation> &attributes) noexcept
{
  for (auto [name, form, consts] : attributes) {
    auto is_indirect = false;
    do {
      is_indirect = false;
      // clang-format off
      switch (form) {
      case AttributeForm::DW_FORM_strp: [[fallthrough]];
      case AttributeForm::DW_FORM_sec_offset: [[fallthrough]];
      case AttributeForm::DW_FORM_line_strp: [[fallthrough]];
      case AttributeForm::DW_FORM_ref_addr:
        current_ptr += unit_data->m_header.format();
        break;
      case AttributeForm::DW_FORM_addr:
        current_ptr += unit_data->m_header.addr_size();
        break;
      case AttributeForm::Reserved: PANIC("Can't handle RESERVED");
      case AttributeForm::DW_FORM_block2:
        current_ptr += read_integral<u16>();
        break;
      case AttributeForm::DW_FORM_block4:
        current_ptr += read_integral<u32>();
        break;

      case AttributeForm::DW_FORM_data16:
        current_ptr += 16;
        break;
      case AttributeForm::DW_FORM_string:
        read_string();
        break;
      case AttributeForm::DW_FORM_exprloc: [[fallthrough]];
      case AttributeForm::DW_FORM_block:
        current_ptr += uleb128();
        break;
      case AttributeForm::DW_FORM_block1:
        current_ptr += read_integral<u8>();
        break;

      case AttributeForm::DW_FORM_strx1: [[fallthrough]];
      case AttributeForm::DW_FORM_ref1: [[fallthrough]];
      case AttributeForm::DW_FORM_addrx1: [[fallthrough]];
      case AttributeForm::DW_FORM_data1: [[fallthrough]];
      case AttributeForm::DW_FORM_flag:
        current_ptr += 1;
        break;

      case AttributeForm::DW_FORM_addrx2: [[fallthrough]];
      case AttributeForm::DW_FORM_strx2: [[fallthrough]];
      case AttributeForm::DW_FORM_ref2: [[fallthrough]];
      case AttributeForm::DW_FORM_data2:
      current_ptr += 2;
        break;

      case AttributeForm::DW_FORM_addrx3: [[fallthrough]];
      case AttributeForm::DW_FORM_strx3:
        current_ptr += 3;
        break;

      case AttributeForm::DW_FORM_addrx4: [[fallthrough]];
      case AttributeForm::DW_FORM_strx4: [[fallthrough]];
      case AttributeForm::DW_FORM_ref4: [[fallthrough]];
      case AttributeForm::DW_FORM_data4:
        current_ptr += 4;
        break;

      case AttributeForm::DW_FORM_ref8: [[fallthrough]];
      case AttributeForm::DW_FORM_data8:
        current_ptr += 8;
        break;

      case AttributeForm::DW_FORM_sdata:
        leb128();
        break;
      case AttributeForm::DW_FORM_rnglistx: [[fallthrough]];
      case AttributeForm::DW_FORM_loclistx: [[fallthrough]];
      case AttributeForm::DW_FORM_addrx: [[fallthrough]];
      case AttributeForm::DW_FORM_strx: [[fallthrough]];
      case AttributeForm::DW_FORM_udata: [[fallthrough]];
      case AttributeForm::DW_FORM_ref_udata:
        uleb128();
        break;
      case AttributeForm::DW_FORM_indirect:
        is_indirect = true;
        form = (AttributeForm)uleb128();
        break;
      case AttributeForm::DW_FORM_flag_present:
        break;
      case AttributeForm::DW_FORM_ref_sup4: PANIC("Unsupported attribute form DW_FORM_ref_sup4");
      case AttributeForm::DW_FORM_strp_sup: PANIC("Unsupported attribute form DW_FORM_strp_sup");
      case AttributeForm::DW_FORM_ref_sig8: PANIC("Unsupported attribute form DW_FORM_ref_sig8");
      case AttributeForm::DW_FORM_ref_sup8: PANIC("Unsupported attribute form DW_FORM_ref_sup8");
      case AttributeForm::DW_FORM_implicit_const:
        break;
      default:
        PANIC("Unknown Attribute Form");
      }
    } while (is_indirect);
    // clang-format on
  }
}

void
DwarfUnitData::load_dies() noexcept
{
  if (dies_read())
    return;
  UnitReader reader{this};

  const auto die_sec_offset = reader.sec_offset();
  u8 uleb_sz = 0;
  const auto abbr_code = reader.uleb128_count_read(uleb_sz);
  ASSERT(abbr_code < m_abbrev_table.size(), "Abbreviation code {} is invalid", abbr_code);
  DLOG("dwarf", "First die in new code: 0x{:x} (code={})", std::uintptr_t(reader.ptr()), abbr_code);
  ASSERT(abbr_code != 0 && m_abbrev_table.size() > 3,
         "Top level DIE expected to not be null (i.e. abbrev code != 0)");
  auto &abbreviation = m_abbrev_table[abbr_code - 1];
  reader.skip_attributes(abbreviation.attributes);
  // Siblings and parent ids stored here
  std::vector<int> parent_node;
  std::vector<int> sibling_node;
  parent_node.push_back(0);
  sibling_node.push_back(0);
  m_unit_die = DebugInfoEntry::create_cu(die_sec_offset, abbr_code, abbreviation.tag, abbreviation.has_children);
  m_unit_die.die_data_offset = uleb_sz;
  m_dies.push_back(m_unit_die);
  bool has_children = abbreviation.has_children;

  ASSERT(has_children, "Compile Unit had no children");
  bool new_level = true;
  while (reader.has_more()) {
    const auto die_sec_offset = reader.sec_offset();
    u8 uleb_sz = 0;
    u64 abbr_code = reader.uleb128_count_read(uleb_sz);
    ASSERT(abbr_code <= m_abbrev_table.size(), "Abbreviation code {} is invalid. Dies processed={}", abbr_code,
           m_dies.size());
    if (abbr_code == 0) {
      if (parent_node.empty())
        break;
      new_level = false;
      parent_node.pop_back();
      sibling_node.pop_back();
      continue;
    }

    if (!new_level) {
      m_dies[sibling_node.back()].set_sibling_id(m_dies.size() - sibling_node.back());
      sibling_node.back() = m_dies.size();
    } else {
      sibling_node.push_back(m_dies.size());
    }

    auto &abbreviation = m_abbrev_table[abbr_code - 1];
    auto new_entry = DebugInfoEntry::create_die(die_sec_offset, abbreviation, m_dies.size() - parent_node.back(),
                                                uleb_sz, NONE_INDEX);
    // new_entry.sec_offset = die_sec_offset;
    // new_entry.die_data_offset = uleb_sz;
    // new_entry.abbrev_code = abbr_code;
    // new_entry.has_children = abbreviation.has_children;
    // new_entry.set_parent_id(m_dies.size() - parent_node.back());
    // new_entry.tag = abbreviation.tag;
    reader.skip_attributes(abbreviation.attributes);
    new_level = abbreviation.has_children;
    if (new_level) {
      parent_node.push_back(m_dies.size());
    }

    m_dies.push_back(new_entry);
  }
  DLOG("mdb", "CU 0x{:x} loaded {} dies", get_id(), m_dies.size());
}

UnitReader::UnitReader(DwarfUnitData *unit_data) noexcept : unit_data(unit_data)
{
  const auto cu_header_sec_offs = unit_data->m_header.get_id();
  const auto first_die_offset = cu_header_sec_offs + unit_data->m_header.header_len();
  DLOG("mdb", "UnitReader for CU at offset 0x{:x}", first_die_offset);
  current_ptr = unit_data->p_obj->elf()->debug_info->offset(first_die_offset);
}

UnitReader::UnitReader(DwarfUnitData *unit_data, const DebugInfoEntry *entry) noexcept : unit_data(unit_data)
{
  ASSERT(entry != nullptr, "No valid DIE was passed to unit reader");
  set_die(*entry);
}

UnrelocatedTraceePointer
UnitReader::read_address() noexcept
{
  ASSERT(current_ptr < unit_data->m_header.end_excl(),
         "Reader fell off of CU data section, possibly reading another CU's data");
  switch (unit_data->m_header.addr_size()) {
  case 4: {
    u32 addr = *(u32 *)current_ptr;
    current_ptr += 4;
    return UnrelocatedTraceePointer{addr};
  }
  case 8: {
    u64 addr = *(u64 *)current_ptr;
    current_ptr += 8;
    return UnrelocatedTraceePointer{addr};
  }
  default:
    PANIC(fmt::format("Currently unsupported address size {}", unit_data->m_header.addr_size()));
  }
  return {nullptr};
}

std::string_view
UnitReader::read_string() noexcept
{
  const std::string_view str{(const char *)current_ptr};
  current_ptr += (str.size() + 1);
  return str;
}

DataBlock
UnitReader::read_block(u64 size) noexcept
{
  const auto tmp = current_ptr;
  current_ptr += size;
  return {.ptr = tmp, .size = size};
}

u64
UnitReader::bytes_read() const noexcept
{
  return static_cast<u64>(current_ptr - unit_data->m_header.data());
}

void
UnitReader::set_die(const DebugInfoEntry &entry) noexcept
{
  current_ptr = objfile()->elf()->debug_info->begin() + entry.sec_offset + entry.die_data_offset;
}

u64
UnitReader::uleb128() noexcept
{
  u64 value;
  current_ptr = decode_uleb128(current_ptr, value);
  return value;
}

i64
UnitReader::leb128() noexcept
{
  i64 value;
  current_ptr = decode_uleb128(current_ptr, value);
  return value;
}

u64
UnitReader::uleb128_count_read(u8 &bytes_read_) noexcept
{
  const auto s = current_ptr;
  const auto value = uleb128();
  bytes_read_ = static_cast<u8>(current_ptr - s);
  return value;
}
i64
UnitReader::leb128_count_read(u8 &bytes_read_) noexcept
{
  const auto s = current_ptr;
  const auto value = leb128();
  bytes_read_ = static_cast<u8>(current_ptr - s);
  return value;
}

u64
UnitReader::read_offset() noexcept
{
  ASSERT(unit_data->m_header.format() == 4 || unit_data->m_header.format() == 8, "Offset size is unsupported: {}",
         unit_data->m_header.format());
  if (unit_data->m_header.format() == 4) {
    return read_integral<u32>();
  } else {
    return read_integral<u64>();
  }
}

bool
UnitReader::has_more() const noexcept
{
  return current_ptr < unit_data->m_header.end_excl();
}

u64
UnitReader::read_section_offset(u64 offset) const noexcept
{
  return unit_data->debug_info_offset() + offset;
}

u64
UnitReader::read_bytes(u8 bytes) noexcept
{
  ASSERT(bytes <= 8, "Can't read more than 8 bytes when interpreting something as a u64: {}", bytes);
  int count = bytes;
  auto result = 0;
  auto shift = 0;
  while (count > 0) {
    const u64 v = read_integral<u8>();
    result |= (v << shift);
    shift += 8;
    bytes--;
  }
  return result;
}

UnrelocatedTraceePointer
UnitReader::read_by_idx_from_addr_table(u64 address_index, std::optional<u64> addr_table_base) const noexcept
{
  ASSERT(objfile()->elf()->debug_addr->m_section_ptr != nullptr, ".debug_addr expected not to be nullptr");
  const auto addr_table_offset = addr_table_base.value_or(0) + address_index * unit_data->m_header.format();
  const auto ptr = (objfile()->elf()->debug_addr->m_section_ptr + addr_table_offset);
  if (unit_data->m_header.addr_size() == 4) {
    const auto value = *(u32 *)ptr;
    return UnrelocatedTraceePointer{value};
  } else {
    const auto value = *(u64 *)ptr;
    return UnrelocatedTraceePointer{value};
  }
}

std::string_view
UnitReader::read_by_idx_from_str_table(u64 address_index, std::optional<u64> str_offsets_base) const noexcept
{
  ASSERT(objfile()->elf()->debug_str_offsets->m_section_ptr != nullptr,
         ".debug_str_offsets expected not to be nullptr");
  const auto str_table_offset = str_offsets_base.value_or(0) + address_index * unit_data->m_header.format();
  const auto ptr = (objfile()->elf()->debug_str_offsets->m_section_ptr + str_table_offset);
  if (unit_data->m_header.addr_size() == 4) {
    const auto value = *(u32 *)ptr;
    return std::string_view{(const char *)(objfile()->elf()->debug_str->m_section_ptr + value)};
  } else {
    const auto value = *(u64 *)ptr;
    return std::string_view{(const char *)(objfile()->elf()->debug_str->m_section_ptr + value)};
  }
}

u64
UnitReader::read_by_idx_from_rnglist(u64 range_index, std::optional<u64> rng_list_base) const noexcept
{
  ASSERT(objfile()->elf()->debug_rnglists->m_section_ptr != nullptr,
         ".debug_str_offsets expected not to be nullptr");

  const auto rnglist_offset = rng_list_base.value_or(0) + range_index * unit_data->m_header.format();
  const auto ptr = (objfile()->elf()->debug_rnglists->m_section_ptr + rnglist_offset);
  if (unit_data->m_header.addr_size() == 4) {
    const auto value = *(u32 *)ptr;
    return value;
  } else {
    const auto value = *(u64 *)ptr;
    return value;
  }
}

u64
UnitReader::read_loclist_index(u64 range_index, std::optional<u64> loc_list_base) const noexcept
{
  ASSERT(objfile()->elf()->debug_loclist->m_section_ptr != nullptr,
         ".debug_str_offsets expected not to be nullptr");

  const auto rnglist_offset = loc_list_base.value_or(0) + range_index * unit_data->m_header.format();
  const auto ptr = (objfile()->elf()->debug_loclist->m_section_ptr + rnglist_offset);
  if (unit_data->m_header.addr_size() == 4) {
    const auto value = *(u32 *)ptr;
    return value;
  } else {
    const auto value = *(u64 *)ptr;
    return value;
  }
}

u64
UnitReader::sec_offset() const noexcept
{
  const auto cu_header_sec_offs = unit_data->m_header.get_id();
  const auto first_cu_offset = cu_header_sec_offs + unit_data->m_header.header_len();
  return first_cu_offset + bytes_read();
}

DwarfUnitData *
prepare_unit_data(ObjectFile *obj_file, const DwarfUnitHeader &header) noexcept
{
  const auto abbrev_sec = obj_file->elf()->debug_abbrev;

  AbbreviationInfo::Table result{};
  const u8 *abbr_ptr = header.abbreviation_data(abbrev_sec);

  while (true) {
    AbbreviationInfo info;
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
  auto dwarf_unit_data = new DwarfUnitData{obj_file, header};
  dwarf_unit_data->set_abbrev(std::move(result));

  return dwarf_unit_data;
}

std::vector<DwarfUnitHeader>
read_cu_headers(ObjectFile *obj) noexcept
{
  const auto dbg_info = obj->elf()->debug_info;
  std::vector<DwarfUnitHeader> result{};
  DwarfBinaryReader reader{dbg_info};
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
    DwarfUnitHeader h{sec_offset, reader.get_span(die_data_len), abb_offs, addr_size,
                      format,     (DwarfVersion)version,         unit_type};
    result.push_back(h);
    ASSERT(reader.bytes_read() == sec_offset + unit_len + init_len,
           "Well, this is wrong. Expected to have read {} bytes, but was at {}", sec_offset + unit_len + init_len,
           reader.bytes_read());
  }
  return result;
}

DwarfUnitDataTask::DwarfUnitDataTask(ObjectFile *obj, DwarfUnitDataTask::Work headers) noexcept
    : utils::Task(), p_obj(obj), m_cu_headers(headers)
{
}

DwarfUnitDataTask::~DwarfUnitDataTask() noexcept {}

void
DwarfUnitDataTask::execute_task() noexcept
{
  std::vector<DwarfUnitData *> result;
  result.reserve(m_cu_headers.size());
  for (const auto &hdr : m_cu_headers) {
    auto unit_data = prepare_unit_data(p_obj, hdr);
    result.push_back(unit_data);
  }
  p_obj->set_unit_data(result);
}

/*static*/
std::vector<DwarfUnitDataTask *>
DwarfUnitDataTask::create_work(ObjectFile *obj, Work work) noexcept
{
  const auto work_sizes = utils::ThreadPool::work_sizes(work, 10);
  auto offset = 0;
  std::vector<DwarfUnitDataTask *> result;
  for (const auto sz : work_sizes) {
    result.push_back(new DwarfUnitDataTask(obj, work.subspan(offset, sz)));
    offset += sz;
  }
  return result;
}

} // namespace sym::dw2