#include "cu.h"
#include "../target.h"
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
                         u32 index, Target *target) noexcept
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
    PANIC("AttributeForm::DW_FORM_ref_addr not yet supported");
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
  const auto abbr_code = reader.uleb128();
  ASSERT(abbr_code != 0, "Top level DIE expected to not be null (i.e. abbrev code != 0)");
  auto abbreviation = abbrev_table[abbr_code - 1];
  root->abbreviation_code = abbr_code;
  root->tag = abbreviation.tag;

  for (const auto &attr : abbreviation.attributes) {
    root->attributes.emplace_back(read_attribute_values(root.get(), reader, attr, abbreviation.implicit_consts));
  }
  root->next_die_in_cu = reader.bytes_read();
  std::stack<DebugInfoEntry *> parent_stack; // for "horizontal" travelling
  DebugInfoEntry *e = root.get();
  bool has_children = abbreviation.has_children;
  while (true) {
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
    auto abbreviation = abbrev_table[abbr_code - 1];
    e->abbreviation_code = abbr_code;
    e->tag = abbreviation.tag;
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
add_subprograms(CompilationUnitFile &file, DebugInfoEntry *root_die) noexcept
{
  for (const auto &child : root_die->children) {
    if (child->subprogram_with_addresses) {
      FunctionSymbol fn{.start = nullptr, .end = nullptr, .name = {}};
      for (const auto attr : child->attributes) {
        using enum Attribute;
        switch (attr.name) {
        case DW_AT_low_pc:
          fn.start = attr.address();
          break;
        case DW_AT_high_pc:
          fn.end = attr.address();
          break;
        case DW_AT_name:
          fn.name = attr.string();
          break;
        case DW_AT_linkage_name:
          break;
        default:
          break; // ignore attributes
        }
      }
      if (fn.start != nullptr && fn.end != nullptr && !fn.name.empty()) {
        // means the AT_high_pc was an offset, not an address
        if (fn.end < fn.start) {
          fn.end = (fn.start + fn.end);
        }
        file.add_function(fn);
      }
    }
    add_subprograms(file, child.get());
  }
}

void
CUProcessor::process_compile_unit_die(DebugInfoEntry *cu_die) noexcept
{
  LineTable ltes;
  const auto elf = obj_file->parsed_elf;
  TPtr<void> low = nullptr;
  TPtr<void> high = nullptr;
  CompilationUnitFile f{cu_die};
  if (header.addr_size == 4) {
    PANIC("32-bit arch not yet supported.");
  } else {
    for (const auto &att : cu_die->attributes) {
      if (att.name == Attribute::DW_AT_name) {
        f.set_name(att.string());
      } else if (att.name == Attribute::DW_AT_ranges) {
        // todo(simon): re-add/re-design for opportunity of aligned loads/stores
        const auto value = att.address();
        const auto ptr = elf->debug_ranges->begin() + value;
        u64 *start = (u64 *)ptr;
        f.add_addr_rng(start);
        for (start += 2; f.m_addr_ranges.back().is_valid(); start += 2) {
          f.add_addr_rng(start);
        }
        f.m_addr_ranges.pop_back();
      } else if (att.name == Attribute::DW_AT_stmt_list) {
        const auto offset = att.address();
        if (header.version == DwarfVersion::D4) {
          line_header = read_lineheader_v4(obj_file->parsed_elf->debug_line->data() + offset, header.addr_size);
          f.set_linetable(parse_linetable(this));
        } else {
          PANIC("V5 line number program not supported yet");
        }
      } else if (att.name == Attribute::DW_AT_low_pc) {
        low = att.address();
      } else if (att.name == Attribute::DW_AT_high_pc) {
        high = att.address();
      }
    }
  }
  f.set_boundaries();
  add_subprograms(f, cu_die);
  requesting_target->add_file(std::move(f));
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

class LNPStateMachine
{
public:
  LNPStateMachine(LineHeader *header, LineTable *table)
      : header{header}, table{table}, address(0), line(1), column(0), op_index(0), file(1),
        is_stmt(header->default_is_stmt), basic_block(false), end_sequence(false), prologue_end(false),
        epilogue_begin(false), isa(0), discriminator(0)
  {
  }

  constexpr bool
  sequence_ended() const noexcept
  {
    return end_sequence;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  stamp_entry() noexcept
  {
    table->push_back(LineTableEntry{.pc = address,
                                    .line = line,
                                    .column = column,
                                    .file = static_cast<u16>(file),
                                    .is_stmt = is_stmt,
                                    .prologue_end = prologue_end,
                                    .basic_block = basic_block,
                                    .epilogue_begin = epilogue_begin});
    discriminator = 0;
    basic_block = false;
    prologue_end = false;
    epilogue_begin = false;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  advance_pc(u64 adjust_value) noexcept
  {
    const auto address_adjust = ((op_index + adjust_value) / header->max_ops) * header->min_len;
    address += address_adjust;
    op_index = ((op_index + adjust_value) % header->max_ops);
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  advance_line(i64 value) noexcept
  {
    line += value;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_file(u64 value) noexcept
  {
    file = value;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_column(u64 value) noexcept
  {
    column = value;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  negate_stmt() noexcept
  {
    is_stmt = !is_stmt;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_basic_block() noexcept
  {
    basic_block = true;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=134
  constexpr void
  const_add_pc() noexcept
  {
    special_opindex_advance(255);
  }

  // DWARF V4 Spec page 120:
  // https://dwarfstd.org/doc/DWARF4.pdf#page=134
  constexpr void
  advance_fixed_pc(u64 advance) noexcept
  {
    address += advance;
    op_index = 0;
  }

  // DWARF V4 Spec page 120:
  // https://dwarfstd.org/doc/DWARF4.pdf#page=134
  constexpr void
  set_prologue_end() noexcept
  {
    prologue_end = true;
  }

  // DWARF V4 Spec page 121:
  // https://dwarfstd.org/doc/DWARF4.pdf#page=135
  constexpr void
  set_epilogue_begin() noexcept
  {
    epilogue_begin = true;
  }

  constexpr void
  set_isa(u64 isa) noexcept
  {
    this->isa = isa;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=130
  constexpr void
  execute_special_opcode(u8 opcode) noexcept
  {
    special_opindex_advance(opcode);
    const auto line_inc = header->line_base + ((opcode - header->opcode_base) % header->line_range);
    line += line_inc;
    stamp_entry();
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_sequence_ended() noexcept
  {
    end_sequence = true;
    stamp_entry();
  }

  constexpr void
  set_address(u64 addr) noexcept
  {
    address = addr;
    op_index = 0;
  }

  constexpr void
  define_file(std::string_view filename, u64 dir_index, u64 last_modified, u64 file_size) noexcept
  {
    header->file_names.push_back(FileEntry{filename, dir_index, file_size, {}, last_modified});
  }

  constexpr void
  set_discriminator(u64 value) noexcept
  {
    discriminator = value;
  }

private:
  constexpr void
  special_opindex_advance(u8 opcode)
  {
    const auto advance = op_advance(opcode);
    const auto new_address = address + header->min_len * ((op_index + advance) / header->max_ops);
    const auto new_op_index = (op_index + advance) % header->max_ops;
    address = new_address;
    op_index = new_op_index;
  }

  constexpr u64
  op_advance(u8 opcode) const noexcept
  {
    const auto adjusted_op = opcode - header->opcode_base;
    const auto advance = adjusted_op / header->line_range;
    return advance;
  }
  LineHeader *header;
  LineTable *table;
  // State machine register
  u64 address;
  u32 line;
  u32 column;
  u16 op_index;
  u32 file;
  bool is_stmt;
  bool basic_block;
  bool end_sequence;
  bool prologue_end;
  bool epilogue_begin;
  u8 isa;
  u32 discriminator;
};

LineTable
parse_linetable(CUProcessor *proc) noexcept
{
  using OpCode = LineNumberProgramOpCode;

  auto hdr = proc->get_lnp_header();
  DwarfBinaryReader reader{hdr->data, hdr->data_length};
  LineTable line_table{};
  while (reader.has_more()) {
    LNPStateMachine state{hdr, &line_table};
    while (reader.has_more() && !state.sequence_ended()) {
      const auto opcode = reader.read_value<OpCode>();
      if (const auto spec_op = std::to_underlying(opcode); spec_op >= hdr->opcode_base) {
        state.execute_special_opcode(spec_op);
        continue;
      }
      if (std::to_underlying(opcode) == 0) {
        // Extended Op Codes
        const auto len = reader.read_uleb128<u64>();
        const auto end = reader.current_ptr() + len;
        auto ext_op = reader.read_value<LineNumberProgramExtendedOpCode>();
        switch (ext_op) {
        case LineNumberProgramExtendedOpCode::DW_LNE_end_sequence:
          state.set_sequence_ended();
          break;
        case LineNumberProgramExtendedOpCode::DW_LNE_set_address:
          if (proc->get_header().addr_size == 4) {
            const auto addr = reader.read_value<u32>();
            state.set_address(addr);
          } else {
            const auto addr = reader.read_value<u64>();
            state.set_address(addr);
          }
          break;
        case LineNumberProgramExtendedOpCode::DW_LNE_define_file: {
          if (proc->get_header().version == DwarfVersion::D4) {
            // https://dwarfstd.org/doc/DWARF4.pdf#page=136
            const auto filename = reader.read_string();
            const auto dir_index = reader.read_uleb128<u64>();
            const auto last_modified = reader.read_uleb128<u64>();
            const auto file_size = reader.read_uleb128<u64>();
            state.define_file(filename, dir_index, last_modified, file_size);
          } else {
            PANIC(fmt::format("DWARF V5 line tables not yet implemented"));
          }
          break;
        }
        case LineNumberProgramExtendedOpCode::DW_LNE_set_discriminator: {
          state.set_discriminator(reader.read_uleb128<u64>());
          break;
        }
        default:
          // Vendor extensions
          while (reader.current_ptr() < end)
            reader.read_value<u8>();
          break;
        }
      }
      switch (opcode) {
      case OpCode::DW_LNS_copy:
        state.stamp_entry();
        break;
      case OpCode::DW_LNS_advance_pc:
        state.advance_pc(reader.read_uleb128<u64>());
        break;
      case OpCode::DW_LNS_advance_line:
        state.advance_line(reader.read_leb128<i64>());
        break;
      case OpCode::DW_LNS_set_file:
        state.set_file(reader.read_uleb128<u64>());
        break;
      case OpCode::DW_LNS_set_column:
        state.set_column(reader.read_uleb128<u64>());
        break;
      case OpCode::DW_LNS_negate_stmt:
        state.negate_stmt();
        break;
      case OpCode::DW_LNS_set_basic_block:
        state.set_basic_block();
        break;
      case OpCode::DW_LNS_const_add_pc:
        state.const_add_pc();
        break;
      case OpCode::DW_LNS_fixed_advance_pc:
        state.advance_fixed_pc(reader.read_value<u16>());
        break;
      case OpCode::DW_LNS_set_prologue_end:
        state.set_prologue_end();
        break;
      case OpCode::DW_LNS_set_epilogue_begin:
        state.set_epilogue_begin();
        break;
      case OpCode::DW_LNS_set_isa:
        state.set_isa(reader.read_value<u64>());
        break;
      }
    }
  }
  return line_table;
}