#include "cu.h"
#include "dwarf.h"
#include "dwarf_utility.h"
#include "elf.h"
#include "objfile.h"
#include <cstdint>
#include <utility>

CompilationUnitBuilder::CompilationUnitBuilder(ObjectFile *obj_file) noexcept : obj_file(obj_file) {}

std::vector<CompileUnitHeader>
CompilationUnitBuilder::build_cu_headers() noexcept
{
  auto it = obj_file->parsed_elf->debug_info->begin();
  auto determine_dwarf = obj_file->get_at<DetermineDwarf>(it);
  if (determine_dwarf->is_32()) {
    if (determine_dwarf->version() == 4) {
      return build_cu_headers_impl<D4<u32>>();
    } else {
      return build_cu_headers_impl<D5<u32>>();
    }
  } else {
    if (determine_dwarf->version() == 4) {
      return build_cu_headers_impl<D4<u64>>();
    } else {
      return build_cu_headers_impl<D5<u64>>();
    }
  }
}

CUProcessor::CUProcessor(const ObjectFile *obj_file, CompileUnitHeader header, AbbreviationInfo::Table &&table,
                         u32 index) noexcept
    : finished(false), file_name{}, obj_file(obj_file), index(index), header(header),
      abbrev_table(std::move(table)), cu_dies()
{
}

// N.B.: todo(simon): implement support for DWZ and split files.
static constexpr auto IS_DWZ = false;

static AttributeValue
read_attribute_values(CompileUnitReader &reader, Abbreviation abbr, std::vector<i64> &implicit_consts) noexcept
{
  if (abbr.IMPLICIT_CONST_INDEX != UINT8_MAX) {
    return AttributeValue{implicit_consts[abbr.IMPLICIT_CONST_INDEX], AttributeForm::DW_FORM_implicit_const,
                          abbr.name};
  }

  const auto elf = reader.obj_file->parsed_elf;

  switch (abbr.form) {
  case AttributeForm::DW_FORM_ref_addr:
    PANIC("AttributeForm::DW_FORM_ref_addr not yet supported");
    break;
  case AttributeForm::DW_FORM_addr:
    return AttributeValue{reader.read_address(), abbr.form, abbr.name};
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
    ASSERT(elf->debug_str != nullptr, ".debug_line expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.read_offset();
      std::string_view indirect_str{(const char *)elf->debug_str->begin() + offset};
      return AttributeValue{indirect_str, abbr.form, abbr.name};
    }
  }
  case AttributeForm::DW_FORM_line_strp: {
    ASSERT(elf->debug_line != nullptr, ".debug_line expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.read_offset();
      std::string_view indirect_str{(const char *)elf->debug_line_str->begin() + offset};
      AttributeValue{indirect_str, abbr.form, abbr.name};
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
    Abbreviation new_abbr{.name = abbr.name, .form = new_form};
    if (new_form == AttributeForm::DW_FORM_implicit_const) {
      const auto value = reader.leb128();
      new_abbr.IMPLICIT_CONST_INDEX = implicit_consts.size();
      implicit_consts.push_back(value);
    }
    return read_attribute_values(reader, new_abbr, implicit_consts);
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
    return AttributeValue{reader.read_by_idx_from_str_table(idx), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_strx: {
    const auto idx = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_str_table(idx), abbr.form, abbr.name};
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
           reader.obj_file->path.c_str());
    const auto base = std::to_underlying(AttributeForm::DW_FORM_addrx1) - 1;
    const auto bytes_to_read = std::to_underlying(abbr.form) - base;
    const auto addr_index = reader.read_bytes(bytes_to_read);
    return AttributeValue{reader.read_by_idx_from_addr_table(addr_index), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_addrx: {
    ASSERT(elf->debug_addr != nullptr, ".debug_addr not read in or found in objfile {}",
           reader.obj_file->path.c_str());
    const auto addr_table_index = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_addr_table(addr_table_index), abbr.form, abbr.name};
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
           reader.obj_file->path.c_str());
    const auto idx = reader.uleb128();
    return AttributeValue{reader.read_loclist_index(idx), abbr.form, abbr.name};
  }

  case AttributeForm::DW_FORM_rnglistx: {
    ASSERT(elf->debug_rnglists != nullptr, ".debug_rnglists not read in or found in objfile {}",
           reader.obj_file->path.c_str());
    const auto addr_table_index = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_rnglist(addr_table_index), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_sup8:
    PANIC("Unsupported attribute form DW_FORM_ref_sup8");
    break;
  }
}

DebugInfoEntry *
CUProcessor::read_in_dies() noexcept
{
  DebugInfoEntry *ancestor = nullptr;
  CompileUnitReader reader{&header, obj_file};
  while (reader.has_more()) {
    const auto abbrev_code = reader.uleb128();
    if (abbrev_code == 0)
      return ancestor;
    auto abbreviation = abbrev_table[abbrev_code - 1];
    std::vector<AttributeValue> attribute_values;

    fmt::println("{} - Has children: {}", abbreviation.tag, abbreviation.has_children);
    for (const auto &attr : abbreviation.attributes) {
      attribute_values.emplace_back(read_attribute_values(reader, attr, abbreviation.implicit_consts));
    }
    for (const auto &attr : attribute_values) {
      if (attr.form == AttributeForm::DW_FORM_strp) {
        fmt::println("\t{} {} => {}", attr.name, attr.form, attr.string());
      } else {
        fmt::println("\t{} {}", attr.name, attr.form);
      }
    }
  }

  ancestor = &cu_dies.front();
  return ancestor;
}

CompileUnitReader::CompileUnitReader(CompileUnitHeader *header, const ObjectFile *obj_file) noexcept
    : obj_file(obj_file), header(header), current_ptr(header->data), addr_table_base()
{
}

UnrelocatedTraceePointer
CompileUnitReader::read_address() noexcept
{
  ASSERT(current_ptr < header->end, "Reader fell off of CU data section, possibly reading another CU's data");
  switch (header->addr_size) {
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
    PANIC(fmt::format("Currently unsupported address size {}", header->addr_size));
  }
  return {nullptr};
}

std::string_view
CompileUnitReader::read_string() noexcept
{
  const std::string_view str{(const char *)current_ptr};
  current_ptr += (str.size() + 1);
  return str;
}

DataBlock
CompileUnitReader::read_block(u64 size) noexcept
{
  const auto tmp = current_ptr;
  current_ptr += size;
  return {.ptr = tmp, .size = size};
}

u64
CompileUnitReader::uleb128() noexcept
{
  u64 value;
  current_ptr = decode_uleb128(current_ptr, value);
  return value;
}

i64
CompileUnitReader::leb128() noexcept
{
  i64 value;
  current_ptr = decode_uleb128(current_ptr, value);
  return value;
}

u64
CompileUnitReader::read_offset() noexcept
{
  ASSERT(header->format == 4 || header->format == 8, "Address size is unsupported: {}", header->format);
  if (header->format == 4) {
    return read_integral<u32>();
  } else {
    return read_integral<u64>();
  }
}

bool
CompileUnitReader::has_more() const noexcept
{
  return current_ptr < header->end;
}

u64
CompileUnitReader::read_section_offset(u64 offset) const noexcept
{
  return header->debug_info_sec_offset + offset;
}

u64
CompileUnitReader::read_bytes(u8 bytes) noexcept
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
CompileUnitReader::read_by_idx_from_addr_table(u64 address_index) const noexcept
{
  ASSERT(obj_file->parsed_elf->debug_addr->m_section_ptr != nullptr, ".debug_addr expected not to be nullptr");
  const auto addr_table_offset = addr_table_base.value_or(0) + address_index * header->format;
  const auto ptr = (obj_file->parsed_elf->debug_addr->m_section_ptr + addr_table_offset);
  if (header->addr_size == 4) {
    const auto value = *(u32 *)ptr;
    return UnrelocatedTraceePointer{value};
  } else {
    const auto value = *(u64 *)ptr;
    return UnrelocatedTraceePointer{value};
  }
}

std::string_view
CompileUnitReader::read_by_idx_from_str_table(u64 address_index) const noexcept
{
  ASSERT(obj_file->parsed_elf->debug_str_offsets->m_section_ptr != nullptr,
         ".debug_str_offsets expected not to be nullptr");
  const auto str_table_offset = str_offsets_base.value_or(0) + address_index * header->format;
  const auto ptr = (obj_file->parsed_elf->debug_str_offsets->m_section_ptr + str_table_offset);
  if (header->addr_size == 4) {
    const auto value = *(u32 *)ptr;
    return std::string_view{(const char *)(obj_file->parsed_elf->debug_str->m_section_ptr + value)};
  } else {
    const auto value = *(u64 *)ptr;
    return std::string_view{(const char *)(obj_file->parsed_elf->debug_str->m_section_ptr + value)};
  }
}

u64
CompileUnitReader::read_by_idx_from_rnglist(u64 range_index) const noexcept
{
  ASSERT(obj_file->parsed_elf->debug_rnglists->m_section_ptr != nullptr,
         ".debug_str_offsets expected not to be nullptr");

  const auto rnglist_offset = rng_list_base.value_or(0) + range_index * header->format;
  const auto ptr = (obj_file->parsed_elf->debug_rnglists->m_section_ptr + rnglist_offset);
  if (header->addr_size == 4) {
    const auto value = *(u32 *)ptr;
    return value;
  } else {
    const auto value = *(u64 *)ptr;
    return value;
  }
}

u64
CompileUnitReader::read_loclist_index(u64 range_index) const noexcept
{
  ASSERT(obj_file->parsed_elf->debug_loclist->m_section_ptr != nullptr,
         ".debug_str_offsets expected not to be nullptr");

  const auto rnglist_offset = loc_list_base.value_or(0) + range_index * header->format;
  const auto ptr = (obj_file->parsed_elf->debug_loclist->m_section_ptr + rnglist_offset);
  if (header->addr_size == 4) {
    const auto value = *(u32 *)ptr;
    return value;
  } else {
    const auto value = *(u64 *)ptr;
    return value;
  }
}