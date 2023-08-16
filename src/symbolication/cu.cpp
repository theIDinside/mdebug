#include "cu.h"
#include "../supervisor.h"
#include "block.h"
#include "dwarf.h"
#include "dwarf_defs.h"
#include "elf.h"
#include "lnp.h"
#include "objfile.h"
#include "type.h"
#include <bit>
#include <bits/align.h>
#include <cstdint>
#include <emmintrin.h>
#include <stack>
#include <utility>

CompilationUnitBuilder::CompilationUnitBuilder(ObjectFile *obj_file) noexcept : obj_file(obj_file) {}

std::vector<CompileUnitHeader>
CompilationUnitBuilder::build_cu_headers() noexcept
{
  VERIFY(
      obj_file->parsed_elf->debug_info != nullptr,
      "Main executable must have dwarf debug information provided. This is an absolute constraint made by MDB.");
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

CUProcessor::CUProcessor(ObjectFile *obj_file, CompileUnitHeader header, AbbreviationInfo::Table &&table,
                         u32 index, TraceeController *target) noexcept
    : finished{false}, file_name{}, obj_file{obj_file}, cu_index{index}, header{header},
      abbrev_table{std::move(table)}, cu_dies{}, cu_file{nullptr}, requesting_target{target}, line_header{nullptr},
      line_table{nullptr}
{
}

// N.B.: todo(simon): implement support for DWZ and split files.
static constexpr auto IS_DWZ = false;

static AttributeValue
read_attribute_values(DebugInfoEntry *e, CompileUnitReader &reader, Abbreviation abbr,
                      std::vector<i64> &implicit_consts) noexcept
{
  if (abbr.IMPLICIT_CONST_INDEX != UINT8_MAX) {
    return AttributeValue{implicit_consts[abbr.IMPLICIT_CONST_INDEX], AttributeForm::DW_FORM_implicit_const,
                          abbr.name};
  }

  const auto elf = reader.obj_file->parsed_elf;

  switch (abbr.form) {
  case AttributeForm::DW_FORM_ref_addr:
    return AttributeValue{reader.read_offset(), abbr.form, abbr.name};
    break;
  case AttributeForm::DW_FORM_addr: {
    e->subprogram_with_addresses = true;
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
    return read_attribute_values(e, reader, new_abbr, implicit_consts);
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
  PANIC("Unknown Attribute Form");
}

std::unique_ptr<DebugInfoEntry>
CUProcessor::read_dies() noexcept
{
  CompileUnitReader reader{&header, obj_file};
  std::unique_ptr<DebugInfoEntry> root = std::make_unique<DebugInfoEntry>();
  const auto die_sec_offset = reader.sec_offset();
  const auto abbr_code = reader.uleb128();

  ASSERT(abbr_code != 0, "Top level DIE expected to not be null (i.e. abbrev code != 0)");
  auto &abbreviation = abbrev_table[abbr_code - 1];
  root->set_abbreviation(abbreviation);
  root->set_offset(die_sec_offset);

  for (const auto &attr : abbreviation.attributes) {
    root->attributes.emplace_back(read_attribute_values(root.get(), reader, attr, abbreviation.implicit_consts));
  }
  std::stack<DebugInfoEntry *> parent_stack; // for "horizontal" travelling
  DebugInfoEntry *e = root.get();
  bool has_children = abbreviation.has_children;
  if (!has_children)
    return root;
  while (true) {
    const auto die_sec_offset = reader.sec_offset();
    u64 abbr_code = reader.uleb128();
    if (abbr_code == 0) {
      parent_stack.pop();
      if (parent_stack.empty())
        break;
      has_children = false;
      continue;
    }
    if (has_children) {
      parent_stack.push(e);
    }
    parent_stack.top()->children.emplace_back(std::make_unique<DebugInfoEntry>());
    e = parent_stack.top()->children.back().get();
    auto &abbreviation = abbrev_table[abbr_code - 1];
    e->set_abbreviation(abbreviation);
    e->set_offset(die_sec_offset);
    for (const auto &attr : abbreviation.attributes) {
      e->attributes.emplace_back(read_attribute_values(e, reader, attr, abbreviation.implicit_consts));
    }
    has_children = abbreviation.has_children;
  }
  return root;
}

const CompileUnitHeader &
CUProcessor::get_header() const noexcept
{
  return header;
}

LineHeader *
CUProcessor::get_lnp_header() const noexcept
{
  ASSERT(line_header.get() != nullptr, "Line Number Program Header has not been read in!");
  return line_header.get();
}

static void
add_subprograms(CompilationUnitFile &file, DebugInfoEntry *root_die, Elf *elf) noexcept
{
  for (const auto &child : root_die->children) {
    if (child->subprogram_with_addresses) {
      FunctionSymbol fn{.start = nullptr, .end = nullptr, .name = {}};
      for (const auto attr : child->attributes) {
        using enum Attribute;
        switch (attr.name) {
        case DW_AT_low_pc:
          fn.start = elf->relocate_addr(attr.address());
          break;
        case DW_AT_high_pc:
          fn.end = elf->relocate_addr(attr.address());
          break;
        case DW_AT_name:
          fn.name = attr.string();
          DLOG("dwarf", "[cu] die=0x{:x}, subprogram={}", child->sec_offset, fn.name);
          break;
        case DW_AT_linkage_name:
          if (fn.name.empty()) {
            // TODO(simon): this will require demangling to make sense at all. For now just record the mangled
            // name. Damn you overloading!
            fn.name = attr.string();
          }
          break;
        default:
          break; // ignore attributes
        }
      }
      if (fn.start != nullptr && fn.end != nullptr && !fn.name.empty()) {
        // means the AT_high_pc was an offset, not an address
        if (fn.end < fn.start) {
          fn.end = elf->relocate_addr(fn.start + fn.end);
        }
        file.add_function(fn);
      }
    }
    add_subprograms(file, child.get(), elf);
  }
}

std::optional<AddressRange>
CUProcessor::determine_unrelocated_bounds(DebugInfoEntry *die) const noexcept
{
  const auto h = die->get_attribute(Attribute::DW_AT_high_pc);
  if (h) {
    const auto l = die->get_attribute(Attribute::DW_AT_low_pc);
    return zip(l, h, [](const auto &l, const auto &h) {
      if (h.form != AttributeForm::DW_FORM_addr)
        return AddressRange{l.address(), l.address() + h.address()};
      else
        return AddressRange{l.address(), h.address()};
    });
  }

  if (const auto r = die->get_attribute(Attribute::DW_AT_ranges); r) {
    const u64 offset = r.value().address();
    const auto elf = obj_file->parsed_elf;
    if (header.version == DwarfVersion::D4) {
      DwarfBinaryReader reader{elf->debug_ranges, offset};
      BoundsBuilder builder{};
      while (true) {
        if (!builder.next(reader.read_value<u64>(), reader.read_value<u64>()))
          break;
      }
      ASSERT(builder.valid(),
             "Failed to determine PC bounds from CU that contains .debug_ranges section reference.");
      return builder.done(nullptr);
    } else {
      DwarfBinaryReader reader{elf->debug_rnglists, offset};
      auto range_entry_type = reader.read_value<RangeListEntry>();
      BoundsBuilder builder{};

      while (range_entry_type != RangeListEntry::DW_RLE_end_of_list) {
        switch (range_entry_type) {
        case RangeListEntry::DW_RLE_start_length: {
          builder.next(reader.read_value<u64>(), reader.read_uleb128<u64>());
        } break;
        case RangeListEntry::DW_RLE_offset_pair: {
          TODO_FMT("DW_RLE_offset_pair not handled yet");
          builder.next(reader.read_uleb128<u64>(), reader.read_uleb128<u64>());
        } break;
        default:
          TODO_FMT("RangeListEntry of type {} not yet implemented", to_str(range_entry_type));
          break;
        }
        range_entry_type = reader.read_value<RangeListEntry>();
      }
      return builder.done(nullptr);
    }
  }
  DLOG("mdb", "[die] offset=0x{:x}, no bounds", die->sec_offset);
  return std::nullopt;
}

void
CUProcessor::process_compile_unit_die(DebugInfoEntry *cu_die) noexcept
{
  LineTable ltes;
  const auto elf = obj_file->parsed_elf;

  CompilationUnitFile f{cu_die};
  if (header.addr_size == 4) {
    PANIC("32-bit arch not yet supported.");
  } else {
    const auto bounds = determine_unrelocated_bounds(cu_die);
    if (bounds) {
      f.set_boundaries(*bounds.transform([elf](auto range) {
        return AddressRange{.low = elf->relocate_addr(range.low), .high = elf->relocate_addr(range.high)};
      }));
    }
    for (const auto &att : cu_die->attributes) {
      if (att.name == Attribute::DW_AT_name) {
        f.set_name(att.string());
      } else if (att.name == Attribute::DW_AT_ranges) {
        // todo(simon): re-add/re-design for opportunity of aligned loads/stores
        const u64 value = att.address();
        if (header.version == DwarfVersion::D4) {
          DwarfBinaryReader reader{elf->debug_ranges, value};
          while (true) {
            auto start = reader.read_value<u64>();
            auto end = reader.read_value<u64>();
            if (start == 0 && end == 0)
              break;
            f.add_addr_rng(elf->relocate_addr(start), elf->relocate_addr(end));
          }
        } else {
          DwarfBinaryReader reader{elf->debug_rnglists, value};
          auto range_entry_type = reader.read_value<RangeListEntry>();
          while (range_entry_type != RangeListEntry::DW_RLE_end_of_list) {
            switch (range_entry_type) {
            case RangeListEntry::DW_RLE_start_length: {
              u64 start = reader.read_value<u64>();
              u64 length = reader.read_uleb128<u64>();
              f.add_addr_rng(elf->relocate_addr(start), elf->relocate_addr(start + length));
            } break;
            case RangeListEntry::DW_RLE_offset_pair: {
              u64 start = reader.read_uleb128<u64>();
              u64 end = reader.read_uleb128<u64>();
              f.add_addr_rng(elf->relocate_addr(start), elf->relocate_addr(end));
            } break;
            default:
              TODO_FMT("RangeListEntry of type {} not yet implemented", to_str(range_entry_type));
              break;
            }
            range_entry_type = reader.read_value<RangeListEntry>();
          }
        }
      } else if (att.name == Attribute::DW_AT_stmt_list) {
        const auto offset = att.address();
        auto header = obj_file->line_table_header(offset);
        header->parse_linetable(elf->relocate_addr(nullptr), bounds);
        f.set_linetable(header);
      } else if (att.name == Attribute::DW_AT_low_pc) {
        const auto low = att.address();
        if (!cu_die->get_attribute(Attribute::DW_AT_high_pc)) {
          f.set_default_base_addr(low);
        }
      }
    }
  }
  add_subprograms(f, cu_die, elf);
  requesting_target->add_file(obj_file, std::move(f));
}

AddrPtr
CUProcessor::reloc_base() const noexcept
{
  return obj_file->parsed_elf->relocate_addr(nullptr);
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
CompileUnitReader::bytes_read() const noexcept
{
  return static_cast<u64>(current_ptr - header->data);
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

u64
CompileUnitReader::sec_offset() const noexcept
{
  return header->debug_info_sec_offset + header->header_length + bytes_read();
}