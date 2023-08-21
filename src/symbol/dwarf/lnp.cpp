#include "lnp.h"
#include "../block.h"
#include "../elf.h"
#include <algorithm>
#include <optional>
#include <unordered_map>
#include <variant>

// SYMBOLS DWARF namespace
namespace sym::dw {

class LNPStateMachine
{
public:
  LNPStateMachine(LineHeader *header, LineTable *table, AddrPtr relocate_base,
                  std::optional<AddressRange> valid_bounds) noexcept
      : header{header}, table(table), relocate_base(relocate_base), address(0), line(1), column(0), op_index(0),
        file(1), is_stmt(header->default_is_stmt), basic_block(false), end_sequence(false), prologue_end(false),
        epilogue_begin(false), isa(0), discriminator(0), bounds(valid_bounds)
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
    if (should_record_lines) {
      table->push_back(LineTableEntry{.pc = address + relocate_base,
                                      .line = line,
                                      .column = column,
                                      .file = static_cast<u16>(file),
                                      .is_stmt = is_stmt,
                                      .prologue_end = prologue_end,
                                      .basic_block = basic_block,
                                      .epilogue_begin = epilogue_begin});
    }
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
    should_record_lines = true;
  }

  constexpr void
  set_address(u64 addr) noexcept
  {
    if (this->bounds && should_record_lines) {
      should_record_lines = AddrPtr{addr} >= bounds->low;
    }
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
  AddrPtr relocate_base;
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
  std::optional<AddressRange> bounds;
  bool should_record_lines = true;
};

u64
read_content_index(DwarfBinaryReader &reader, AttributeForm form)
{
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_udata:
    return reader.read_uleb128<u64>();
  case DW_FORM_data1:
    return reader.read_value<u8>();
  case DW_FORM_data2:
    return reader.read_value<u16>();
  default:
    PANIC(fmt::format("Unsupported form for dir index {}", form));
  }
}

std::string_view
read_content_str(DwarfBinaryReader &reader, AttributeForm form, const Elf *elf)
{
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return reader.read_string();
  case DW_FORM_line_strp:
    ASSERT(elf->debug_line != nullptr, "Reading value of form DW_FORM_line_strp requires .debug_line section");
    return std::string_view{(const char *)elf->debug_line->offset(reader.read_offset())};
  case DW_FORM_strp:
    ASSERT(elf->debug_str != nullptr, "Reading value of form DW_FORM_strp requires .debug_str section");
    return std::string_view{(const char *)elf->debug_str->offset(reader.read_offset())};
  case DW_FORM_strp_sup:
  case DW_FORM_strx:
  case DW_FORM_strx1:
  case DW_FORM_strx2:
  case DW_FORM_strx3:
  case DW_FORM_strx4:
  default:
    PANIC(fmt::format("Reading string of form {} not yet supported", form));
  }
}

DataBlock
read_content_datablock(DwarfBinaryReader &reader, AttributeForm form)
{
  switch (form) {
  case AttributeForm::DW_FORM_data16:
    return reader.read_block(16);
  case AttributeForm::DW_FORM_block: {
    const auto sz = reader.read_uleb128<u64>();
    return reader.read_block(sz);
  }
  default:
    PANIC(fmt::format("Unsupported block form {}", form));
  }
}

std::variant<std::string_view, u64, DataBlock>
read_content(DwarfBinaryReader &reader, AttributeForm form)
{
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return reader.read_string();
  case DW_FORM_line_strp:
    [[fallthrough]];
  case DW_FORM_strp:
    [[fallthrough]];
  case DW_FORM_strp_sup:
    return reader.dwarf_spec_read_value();
  case DW_FORM_udata:
    return reader.read_uleb128<u64>();
  case DW_FORM_data1:
    return reader.read_value<u8>();
  case DW_FORM_data2:
    return reader.read_value<u16>();
  case DW_FORM_data4:
    return reader.read_value<u32>();
  case DW_FORM_data8:
    return reader.read_value<u64>();
  case DW_FORM_data16:
    return reader.read_block(16);
  case DW_FORM_block: {
    const auto sz = reader.read_uleb128<u64>();
    return reader.read_block(sz);
  }
  default:
    PANIC(fmt::format("Unacceptable form {} while reading LNP content description", form));
  }
}

std::vector<LineHeader>
parse_lnp_headers(const sym::Elf *elf) noexcept
{
  ASSERT(elf != nullptr, "ELF must be parsed first");
  auto debug_line = elf->debug_line;
  ASSERT(debug_line != nullptr && debug_line->get_name() == ".debug_line", "Must pass .debug_line ELF section");
  auto header_count = 0u;
  // determine header count
  {
    DwarfBinaryReader reader{debug_line};
    while (reader.has_more()) {
      header_count++;
      const auto init_len = reader.read_initial_length<DwarfBinaryReader::Ignore>();
      reader.skip(init_len);
    }
  }

  std::vector<LineHeader> headers{};
  headers.reserve(header_count);
  DwarfBinaryReader reader{debug_line};

  u8 addr_size = 8u;
  for (auto i = 0u; i < header_count; ++i) {
    const auto sec_offset = reader.bytes_read();
    const auto init_len = reader.read_initial_length<DwarfBinaryReader::Ignore>();
    const auto ptr = reader.current_ptr();
    reader.bookmark();
    const auto version = reader.read_value<u16>();
    ASSERT(version == 4 || version == 5, "Unsupported line number program version: {}", version);
    if (version == 5) {
      addr_size = reader.read_value<u8>();
      // don't care for segment selector size
      reader.skip(1);
    }

    const u64 header_length = reader.dwarf_spec_read_value();
    const auto data_ptr = reader.current_ptr() + header_length;
    const u8 min_ins_len = reader.read_value<u8>();
    const u8 max_ops_per_ins = reader.read_value<u8>();
    const bool default_is_stmt = reader.read_value<u8>();
    const i8 line_base = reader.read_value<i8>();
    const u8 line_range = reader.read_value<u8>();
    const u8 opcode_base = reader.read_value<u8>();
    std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> opcode_lengths{};
    reader.read_into_array(opcode_lengths);

    if (version == 4) {
      // read include directories
      std::vector<DirEntry> dirs;
      auto dir = reader.read_string();
      while (dir.size() > 0) {
        dirs.push_back(DirEntry{.path = dir, .md5 = {}});
        dir = reader.read_string();
      }

      std::vector<FileEntry> files;
      while (reader.peek_value<u8>() != 0) {
        FileEntry entry;
        entry.file_name = reader.read_string();
        entry.dir_index = reader.read_uleb128<u64>();
        [[gnu::unused]] const auto _timestamp = reader.read_uleb128<u64>();
        entry.file_size = reader.read_uleb128<u64>();
        files.push_back(entry);
      }
      headers.push_back(LineHeader{.sec_offset = sec_offset,
                                   .initial_length = init_len,
                                   .data = data_ptr,
                                   .data_end = ptr + init_len,
                                   .version = (DwarfVersion)version,
                                   .addr_size = addr_size,
                                   .min_len = min_ins_len,
                                   .max_ops = max_ops_per_ins,
                                   .default_is_stmt = default_is_stmt,
                                   .line_base = line_base,
                                   .line_range = line_range,
                                   .opcode_base = opcode_base,
                                   .std_opcode_lengths = opcode_lengths,
                                   .directories = std::move(dirs),
                                   .file_names = std::move(files),
                                   .line_table = nullptr});
      reader.skip(init_len - reader.pop_bookmark());
    } else {
      const u8 directory_entry_format_count = reader.read_value<u8>();
      LineHeader::DirEntFormats dir_entry_fmt{};
      dir_entry_fmt.reserve(directory_entry_format_count);

      for (auto i = 0; i < directory_entry_format_count; i++) {
        const auto content = reader.read_uleb128<LineNumberProgramContent>();
        const auto form = reader.read_uleb128<AttributeForm>();
        dir_entry_fmt.emplace_back(content, form);
      }

      const u64 dir_count = reader.read_uleb128<u64>();
      std::vector<DirEntry> dirs{};
      dirs.reserve(dir_count);
      for (auto i = 0ull; i < dir_count; i++) {
        using enum AttributeForm;
        DirEntry ent{};

        for (const auto &[content, form] : dir_entry_fmt) {
          if (content == LineNumberProgramContent::DW_LNCT_path) {
            ent.path = read_content_str(reader, form, elf);
          } else if (content == LineNumberProgramContent::DW_LNCT_MD5) {
            ent.md5.emplace(read_content_datablock(reader, form));
          } else {
            read_content(reader, form);
          }
        }
        dirs.push_back(ent);
      }

      const u8 file_name_entry_fmt_count = reader.read_value<u8>();
      LineHeader::FileNameEntFormats filename_ent_formats{};
      filename_ent_formats.reserve(file_name_entry_fmt_count);

      for (auto i = 0; i < file_name_entry_fmt_count; i++) {
        const auto content = reader.read_uleb128<LineNumberProgramContent>();
        const auto form = reader.read_uleb128<AttributeForm>();
        filename_ent_formats.emplace_back(content, form);
      }
      const u64 file_count = reader.read_uleb128<u64>();
      std::vector<FileEntry> files{};
      files.reserve(file_count);
      for (auto i = 0ull; i < file_count; i++) {
        FileEntry entry;
        for (const auto &[content, form] : filename_ent_formats) {
          if (content == LineNumberProgramContent::DW_LNCT_directory_index) {
            entry.dir_index = read_content_index(reader, form);
          } else if (content == LineNumberProgramContent::DW_LNCT_MD5) {
            entry.md5.emplace(read_content_datablock(reader, form));
          } else if (content == LineNumberProgramContent::DW_LNCT_path) {
            entry.file_name = read_content_str(reader, form, elf);
          } else {
            read_content(reader, form);
          }
        }
        files.push_back(entry);
      }
      headers.push_back(LineHeader{.sec_offset = sec_offset,
                                   .initial_length = init_len,
                                   .data = data_ptr,
                                   .data_end = ptr + init_len,
                                   .version = (DwarfVersion)version,
                                   .addr_size = addr_size,
                                   .min_len = min_ins_len,
                                   .max_ops = max_ops_per_ins,
                                   .default_is_stmt = default_is_stmt,
                                   .line_base = line_base,
                                   .line_range = line_range,
                                   .opcode_base = opcode_base,
                                   .std_opcode_lengths = opcode_lengths,
                                   .directories = std::move(dirs),
                                   .file_names = std::move(files),
                                   .line_table = nullptr});
      reader.skip(init_len - reader.pop_bookmark());
    }
  }
  DLOG("dwarf", "[lnp]: parsed {} headers", headers.size());
  ASSERT(!reader.has_more(),
         ".debug_line section is expected to have been consumed here, but {} bytes were remaining",
         reader.remaining_size());
  return headers;
}

DwarfBinaryReader
LineHeader::get_reader() const noexcept
{
  return DwarfBinaryReader{data, static_cast<u64>(data_end - data)};
}

bool
LineHeader::has_entries() const noexcept
{
  return line_table && !line_table->empty();
}

void
LineHeader::set_linetable_storage(LineTable *storage) noexcept
{
  line_table = storage;
}

void
LineHeader::parse_linetable(AddrPtr reloc_base, std::optional<sym::AddressRange> bounds) noexcept
{
  using OpCode = LineNumberProgramOpCode;
  auto reader = get_reader();
  std::vector<LineTable> sequences{};
  sequences.push_back({});
  while (reader.has_more()) {
    if (!sequences.empty() && !sequences.back().empty())
      sequences.push_back({});
    LNPStateMachine state{this, &sequences.back(), reloc_base, bounds};
    while (reader.has_more() && !state.sequence_ended()) {
      const auto opcode = reader.read_value<OpCode>();
      if (const auto spec_op = std::to_underlying(opcode); spec_op >= opcode_base) {
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
          if (addr_size == 4) {
            const auto addr = reader.read_value<u32>();
            state.set_address(addr);
          } else {
            const auto addr = reader.read_value<u64>();
            state.set_address(addr);
          }
          break;
        case LineNumberProgramExtendedOpCode::DW_LNE_define_file: {
          if (version == DwarfVersion::D4) {
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
  // N.B: This kind of double work always irks me. But it *is* simple.
  // optimizations possible here.
  std::erase_if(sequences, [](auto &seq) { return seq.empty(); });
  std::sort(sequences.begin(), sequences.end(), [](auto &a, auto &b) { return a.front().pc < b.front().pc; });
  for (const auto &seq : sequences) {
    std::copy(seq.cbegin(), seq.cend(), std::back_inserter(*line_table));
  }
}
} // namespace sym::dw