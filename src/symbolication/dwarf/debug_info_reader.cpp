#include "debug_info_reader.h"
#include "../objfile.h"
#include "symbolication/dwarf/die.h"
#include <optional>

namespace sym::dw {

UnitReader::UnitReader(UnitData *data) noexcept : compilation_unit(data), current_ptr(nullptr)
{
  const auto &header = compilation_unit->header();
  current_ptr = compilation_unit->get_objfile()->parsed_elf->debug_info->offset(header.header_len() +
                                                                                header.debug_info_offset());
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
        current_ptr += compilation_unit->header().format();
        break;
      case AttributeForm::DW_FORM_addr:
        current_ptr += compilation_unit->header().addr_size();
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

UnrelocatedTraceePointer
UnitReader::read_address() noexcept
{
  ASSERT(current_ptr < compilation_unit->header().end_excl(),
         "Reader fell off of CU data section, possibly reading another CU's data");
  switch (compilation_unit->header().addr_size()) {
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
    PANIC(fmt::format("Currently unsupported address size {}", compilation_unit->header().addr_size()));
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
UnitReader::read_block(u64 block_size) noexcept
{
  const auto tmp = current_ptr;
  current_ptr += block_size;
  return {.ptr = tmp, .size = block_size};
}

u64
UnitReader::bytes_read() const noexcept
{
  return static_cast<u64>(current_ptr - compilation_unit->header().data());
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
  current_ptr = decode_leb128(current_ptr, value);
  return value;
}

LEB128Read<u64>
UnitReader::read_uleb128() noexcept
{
  const auto start = current_ptr;
  u64 value;
  current_ptr = decode_uleb128(current_ptr, value);
  return LEB128Read<u64>{value, static_cast<u8>(current_ptr - start)};
}

LEB128Read<i64>
UnitReader::read_leb128() noexcept
{
  const auto start = current_ptr;
  i64 value;
  current_ptr = decode_leb128(current_ptr, value);
  return LEB128Read<i64>{value, static_cast<u8>(current_ptr - start)};
}

u64
UnitReader::read_offset() noexcept
{
  const auto format = compilation_unit->header().format();
  ASSERT(format == 4 || format == 8, "Unsupported format: {}. Offset sizes supported are 4 and 8", format);
  if (format == 4)
    return read_integral<u32>();
  else
    return read_integral<u64>();
}

u64
UnitReader::read_section_offset(u64 offset) const noexcept
{
  return compilation_unit->header().debug_info_offset() + offset;
}

u64
UnitReader::read_n_bytes(u8 n_bytes) noexcept
{
  ASSERT(n_bytes <= 8, "Can't read more than 8 bytes when interpreting something as a u64: {}", n_bytes);
  auto result = 0;
  auto shift = 0;
  while (n_bytes > 0) {
    const u64 v = read_integral<u8>();
    result |= (v << shift);
    shift += 8;
    n_bytes--;
  }
  return result;
}

UnrelocatedTraceePointer
UnitReader::read_by_idx_from_addr_table(u64 address_index, std::optional<u64> addr_table_base) const noexcept
{
  auto obj = compilation_unit->get_objfile();
  const auto header = compilation_unit->header();
  ASSERT(obj->parsed_elf->debug_addr->m_section_ptr != nullptr, ".debug_addr expected not to be nullptr");
  const auto addr_table_offset = addr_table_base.value_or(0) + address_index * header.format();
  const auto ptr = (obj->parsed_elf->debug_addr->m_section_ptr + addr_table_offset);
  if (header.addr_size() == 4) {
    const auto value = *(u32 *)ptr;
    return UnrelocatedTraceePointer{value};
  } else {
    const auto value = *(u64 *)ptr;
    return UnrelocatedTraceePointer{value};
  }
}

std::string_view
UnitReader::read_by_idx_from_str_table(u64 str_index, std::optional<u64> str_offsets_base) const noexcept
{
  const auto elf = compilation_unit->get_objfile()->parsed_elf;
  ASSERT(elf->debug_str_offsets->m_section_ptr != nullptr, ".debug_str_offsets expected not to be nullptr");
  const auto str_table_offset = str_offsets_base.value_or(0) + str_index * compilation_unit->header().format();
  const auto ptr = (elf->debug_str_offsets->m_section_ptr + str_table_offset);
  if (compilation_unit->header().addr_size() == 4) {
    const auto value = *(u32 *)ptr;
    return std::string_view{(const char *)(elf->debug_str->m_section_ptr + value)};
  } else {
    const auto value = *(u64 *)ptr;
    return std::string_view{(const char *)(elf->debug_str->m_section_ptr + value)};
  }
}

u64
UnitReader::read_by_idx_from_rnglist(u64 range_index, std::optional<u64> rng_list_base) const noexcept
{
  const auto elf = compilation_unit->get_objfile()->parsed_elf;
  ASSERT(elf->debug_rnglists->m_section_ptr != nullptr, ".debug_str_offsets expected not to be nullptr");

  const auto rnglist_offset = rng_list_base.value_or(0) + range_index * compilation_unit->header().format();
  const auto ptr = (elf->debug_rnglists->m_section_ptr + rnglist_offset);
  if (compilation_unit->header().addr_size() == 4) {
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
  const auto elf = compilation_unit->get_objfile()->parsed_elf;
  ASSERT(elf->debug_loclist->m_section_ptr != nullptr, ".debug_str_offsets expected not to be nullptr");

  const auto rnglist_offset = loc_list_base.value_or(0) + range_index * compilation_unit->header().format();
  const auto ptr = (elf->debug_loclist->m_section_ptr + rnglist_offset);
  if (compilation_unit->header().addr_size() == 4) {
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
  const auto cu_header_sec_offs = compilation_unit->header().debug_info_offset();
  const auto first_cu_offset = cu_header_sec_offs + compilation_unit->header().header_len();
  return first_cu_offset + bytes_read();
}

bool
UnitReader::has_more() const noexcept
{
  return current_ptr < compilation_unit->header().end_excl();
}

void
UnitReader::seek_die(const DieMetaData &entry) noexcept
{
  current_ptr = compilation_unit->get_objfile()->parsed_elf->debug_info->begin() + entry.section_offset +
                entry.die_data_offset;
}

Elf *
UnitReader::elf() const noexcept
{
  return compilation_unit->get_objfile()->parsed_elf;
}

const u8 *
UnitReader::ptr() const noexcept
{
  return current_ptr;
}

ObjectFile *
UnitReader::objfile() const noexcept
{
  return compilation_unit->get_objfile();
}

std::optional<AttributeValue>
read_specific_attribute(UnitData *cu, const DieMetaData *die, Attribute attr) noexcept
{
  UnitReader reader{cu};
  reader.seek_die(*die);
  const auto &abbrs = cu->get_abbreviation(die->abbreviation_code);
  for (const auto decl : abbrs.attributes) {
    const auto v = read_attribute_value(reader, decl, abbrs.implicit_consts);
    if (decl.name == attr) {
      return v;
    }
  }
  return std::nullopt;
}

AttributeValue
read_attribute_value(UnitReader &reader, Abbreviation abbr, const std::vector<i64> &implicit_consts) noexcept
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
      ASSERT("mdb", "This implicit const as a dynamic form just FEELS wrong!");
      // const auto value = reader.leb128();
      // new_abbr.IMPLICIT_CONST_INDEX = implicit_consts.size();
      // implicit_consts.push_back(value);
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
    const auto idx = reader.read_n_bytes(bytes_to_read);
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
    const auto addr_index = reader.read_n_bytes(bytes_to_read);
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

} // namespace sym::dw