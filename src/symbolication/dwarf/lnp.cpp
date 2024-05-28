#include "lnp.h"
#include "common.h"
#include "symbolication/dwarf_defs.h"
#include "utils/enumerator.h"
#include <algorithm>
#include <set>
#include <symbolication/block.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>

namespace sym::dw {
using FileIndex = u32;

class SourceCodeFileLNPResolver
{
public:
  SourceCodeFileLNPResolver(LNPHeader *header, std::set<LineTableEntry> &table,
                            std::optional<AddressRange> valid_bounds, u32 file_index) noexcept
      : header{header}, table(table), is_stmt(header->default_is_stmt), bounds(valid_bounds),
        file_index(file_index)
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
    if (should_record_lines()) {
      table.insert(LineTableEntry{.pc = address,
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

  bool
  should_record_lines() const noexcept
  {
    return file == file_index;
  }

  LNPHeader *header;
  std::set<LineTableEntry> &table;
  // State machine register
  u64 address{0};
  u32 line{1};
  u32 column{0};
  u16 op_index{0};
  u32 file{1};
  bool is_stmt;
  bool basic_block{false};
  bool end_sequence{false};
  bool prologue_end{false};
  bool epilogue_begin{false};
  u8 isa{0};
  u32 discriminator{0};
  std::optional<AddressRange> bounds;
  u32 file_index;
};

class LNPStateMachine
{
public:
  LNPStateMachine(LNPHeader *header, std::vector<LineTableEntry> *table,
                  std::optional<AddressRange> valid_bounds) noexcept
      : header{header}, table(table), is_stmt(header->default_is_stmt), bounds(valid_bounds)
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
      table->push_back(LineTableEntry{.pc = address,
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
  LNPHeader *header;
  std::vector<LineTableEntry> *table;
  // State machine register
  u64 address{0};
  u32 line{1};
  u32 column{0};
  u16 op_index{0};
  u32 file{1};
  bool is_stmt;
  bool basic_block{false};
  bool end_sequence{false};
  bool prologue_end{false};
  bool epilogue_begin{false};
  u8 isa{0};
  u32 discriminator{0};
  std::optional<AddressRange> bounds;
  bool should_record_lines = true;
};

LNPHeader::LNPHeader(u64 section_offset, u64 initial_length, const u8 *data, const u8 *data_end,
                     DwarfVersion version, u8 addr_size, u8 min_len, u8 max_ops, bool default_is_stmt,
                     i8 line_base, u8 line_range, u8 opcode_base, OpCodeLengths opcode_lengths,
                     std::vector<DirEntry> &&directories, std::vector<FileEntry> &&file_names) noexcept
    : sec_offset(section_offset), initial_length(initial_length), data(data), data_end(data_end), version(version),
      addr_size(addr_size), min_len(min_len), max_ops(max_ops), default_is_stmt(default_is_stmt),
      line_base(line_base), line_range(line_range), opcode_base(opcode_base), std_opcode_lengths(opcode_lengths),
      directories(std::move(directories)), file_names(std::move(file_names))
{
}

std::vector<std::filesystem::path>
LNPHeader::files() const noexcept
{
  std::vector<std::filesystem::path> files{};
  files.reserve(file_names.size());
  std::string path_buf{};
  path_buf.reserve(1024);
  for (const auto &f : file_names) {
    path_buf.clear();
    const auto index = lnp_index(f.dir_index, version);
    // this should be safe, because the string_views (which we call .data() on) are originally null-terminated
    // and we have not made copies.
    fmt::format_to(std::back_inserter(path_buf), "{}/{}", directories[index].path, f.file_name);
    files.emplace_back(std::filesystem::path{path_buf}.lexically_normal());
  }
  return files;
}

std::optional<Path>
LNPHeader::file(u32 f_index) const noexcept
{
  const auto adjusted_index = version == DwarfVersion::D4 ? (f_index == 0 ? 0 : f_index - 1) : f_index;
  if (adjusted_index >= file_names.size()) {
    return {};
  }

  for (const auto &[i, f] : utils::EnumerateView(file_names)) {
    if (i == adjusted_index) {
      const auto dir_index = lnp_index(f.dir_index, version);
      return std::filesystem::path{fmt::format("{}/{}", directories[dir_index].path, f.file_name)}
        .lexically_normal();
    }
  }

  return std::nullopt;
}

std::optional<u32>
LNPHeader::file_entry_index(const std::filesystem::path &p) const noexcept
{
  std::string path_buf{};
  path_buf.reserve(1024);
  auto file_index = 0;
  for (const auto &f : file_names) {
    path_buf.clear();
    const auto index = lnp_index(f.dir_index, version);
    fmt::format_to(std::back_inserter(path_buf), "{}/{}", directories[index].path, f.file_name);
    const auto file_path = std::filesystem::path{path_buf}.lexically_normal();
    if (p == file_path) {
      return file_index + 1;
    }
    ++file_index;
  }
  return std::nullopt;
}

RelocatedLteIterator::RelocatedLteIterator(RelocatedLteIterator::Iter iter, AddrPtr base) noexcept
    : it(iter), base(base)
{
}

bool
LineTable::is_valid() const noexcept
{
  return ltes != nullptr && line_header != nullptr;
}

RelocatedLteIterator
LineTable::begin() const noexcept
{
  return RelocatedLteIterator(ltes->table.cbegin(), relocated_base);
}

RelocatedLteIterator
LineTable::end() const noexcept
{
  return RelocatedLteIterator(ltes->table.cend(), relocated_base);
}

LineTableEntry
LineTable::front() const noexcept
{
  ASSERT(!ltes->table.empty(), "[0x{:x}] Line Table has no entries!", line_header->sec_offset);
  auto first = begin();
  return *first;
}

LineTableEntry
LineTable::back() const noexcept
{
  ASSERT(!ltes->table.empty(), "[0x{:x}] Line Table has no entries!", line_header->sec_offset);
  auto last = end()--;
  return *last;
}

bool
LineTable::no_entries() const noexcept
{
  return ltes->table.empty();
}

u64
LineTable::table_id() const noexcept
{
  return line_header->sec_offset;
}

std::optional<sym::dw::DirEntry>
LineTable::directory(u64 dir_index) const noexcept
{
  ASSERT(line_header && dir_index < line_header->directories.size(), "dir_index={} not found in {} dirs",
         dir_index, line_header->directories.size());
  return line_header->directories[dir_index];
}

std::optional<sym::dw::FileEntry>
LineTable::file(u64 file_index) const noexcept
{
  const auto adjusted = lnp_index(file_index, line_header->version);
  ASSERT(line_header, "Line table doesn't have a line number program header");
  ASSERT(adjusted < line_header->file_names.size(), "file_index={} not found in {} files", adjusted,
         line_header->file_names.size());

  return line_header->file_names[adjusted];
}

RelocatedLteIterator
LineTable::find_by_pc(AddrPtr addr) noexcept
{
  auto start = begin();
  if ((*start).pc == addr) {
    return start;
  }

  auto it =
    std::lower_bound(begin(), end(), addr, [](const LineTableEntry &lte, AddrPtr pc) { return lte.pc < pc; });
  if (it == end()) {
    return end();
  }

  return it;
}

u64
LineTable::size() const noexcept
{
  return this->ltes->table.size();
}

LineTable::LineTable() noexcept : relocated_base(nullptr), line_header(nullptr), ltes(nullptr) {}

LineTable::LineTable(LNPHeader *header, ParsedLineTableEntries *ltes, AddrPtr relocated_base) noexcept
    : relocated_base(relocated_base), line_header(std::move(header)), ltes(ltes)
{
}

LineTableEntry
RelocatedLteIterator::operator*()
{
  return get();
}

LineTableEntry
RelocatedLteIterator::get() const noexcept
{
  auto lte = *it;
  lte.pc += base.get();
  return lte;
}

RelocatedLteIterator
RelocatedLteIterator::operator+(difference_type diff) const noexcept
{
  auto copy = *this;
  return copy += diff;
}

RelocatedLteIterator
RelocatedLteIterator::operator-(difference_type diff) const noexcept
{
  auto copy = *this;
  return copy -= diff;
}

RelocatedLteIterator::difference_type
RelocatedLteIterator::operator-(RelocatedLteIterator other) const noexcept
{
  return it - other.it;
}

RelocatedLteIterator &
RelocatedLteIterator::operator+=(difference_type diff) noexcept
{
  it += diff;
  return *this;
}

RelocatedLteIterator &
RelocatedLteIterator::operator-=(difference_type diff) noexcept
{
  it -= diff;
  return *this;
}

RelocatedLteIterator &
RelocatedLteIterator::operator++() noexcept
{
  ++it;
  return *this;
}

RelocatedLteIterator
RelocatedLteIterator::operator++(int) noexcept
{
  auto copy = *this;
  ++copy.it;
  return copy;
}

RelocatedLteIterator &
RelocatedLteIterator::operator--() noexcept
{
  --it;
  return *this;
}

RelocatedLteIterator
RelocatedLteIterator::operator--(int) noexcept
{
  auto copy = *this;
  --copy.it;
  return copy;
}

bool
operator==(const RelocatedLteIterator &l, const RelocatedLteIterator &r)
{
  return l.it == r.it;
}

bool
operator!=(const RelocatedLteIterator &l, const RelocatedLteIterator &r)
{
  return !(l == r);
}

bool
operator<(const RelocatedLteIterator &l, const RelocatedLteIterator &r)
{
  return l.it < r.it;
}

bool
operator>(const RelocatedLteIterator &l, const RelocatedLteIterator &r)
{
  return l.it > r.it;
}

bool
operator<=(const RelocatedLteIterator &l, const RelocatedLteIterator &r)
{
  return l.it <= r.it;
}

bool
operator>=(const RelocatedLteIterator &l, const RelocatedLteIterator &r)
{
  return l.it >= r.it;
}

void
compute_line_number_program(ParsedLineTableEntries &parsed_lte, const Elf *elf, LNPHeader *header)
{
  DBGLOG(dwarf, "[lnp]: computing lnp at 0x{:x}", header->sec_offset);
  using OpCode = LineNumberProgramOpCode;
  DwarfBinaryReader reader{elf, header->data, static_cast<u64>(header->data_end - header->data)};
  std::vector<std::vector<LineTableEntry>> sequences{};
  sequences.push_back({});
  while (reader.has_more()) {
    if (!sequences.empty() && !sequences.back().empty()) {
      sequences.push_back({});
    }
    LNPStateMachine state{header, &sequences.back(), std::nullopt};
    while (reader.has_more() && !state.sequence_ended()) {
      const auto opcode = reader.read_value<OpCode>();
      if (const auto spec_op = std::to_underlying(opcode); spec_op >= header->opcode_base) {
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
          if (header->addr_size == 4) {
            const auto addr = reader.read_value<u32>();
            state.set_address(addr);
          } else {
            const auto addr = reader.read_value<u64>();
            state.set_address(addr);
          }
          break;
        case LineNumberProgramExtendedOpCode::DW_LNE_define_file: {
          if (header->version == DwarfVersion::D4) {
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
          while (reader.current_ptr() < end) {
            reader.read_value<u8>();
          }
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
    std::copy(seq.cbegin(), seq.cend(), std::back_inserter(parsed_lte.table));
  }
}

std::shared_ptr<std::vector<LNPHeader>>
read_lnp_headers(const Elf *elf) noexcept
{
  ASSERT(elf != nullptr, "ELF must be parsed first");
  auto debug_line = elf->debug_line;
  ASSERT(debug_line != nullptr && debug_line->get_name() == ".debug_line", "Must pass .debug_line ELF section");
  auto header_count = 0u;
  // determine header count
  {
    DwarfBinaryReader reader{elf, debug_line};
    while (reader.has_more()) {
      header_count++;
      const auto init_len = reader.read_initial_length<DwarfBinaryReader::Ignore>();
      reader.skip(init_len);
    }
  }

  std::shared_ptr<std::vector<LNPHeader>> headers = std::make_shared<std::vector<LNPHeader>>();
  headers->reserve(header_count);
  DwarfBinaryReader reader{elf, debug_line};

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
      headers->emplace_back(sec_offset, init_len, data_ptr, ptr + init_len, (DwarfVersion)version, addr_size,
                            min_ins_len, max_ops_per_ins, default_is_stmt, line_base, line_range, opcode_base,
                            opcode_lengths, std::move(dirs), std::move(files));
      reader.skip(init_len - reader.pop_bookmark());
    } else {
      const u8 directory_entry_format_count = reader.read_value<u8>();
      LNPHeader::DirEntFormats dir_entry_fmt{};
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
            ent.path = reader.read_content_str(form);
          } else if (content == LineNumberProgramContent::DW_LNCT_MD5) {
            ent.md5.emplace(reader.read_content_datablock(form));
          } else {
            reader.read_content(form);
          }
        }
        dirs.push_back(ent);
      }

      const u8 file_name_entry_fmt_count = reader.read_value<u8>();
      LNPHeader::FileNameEntFormats filename_ent_formats{};
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
            entry.dir_index = reader.read_content_index(form);
          } else if (content == LineNumberProgramContent::DW_LNCT_MD5) {
            entry.md5.emplace(reader.read_content_datablock(form));
          } else if (content == LineNumberProgramContent::DW_LNCT_path) {
            entry.file_name = reader.read_content_str(form);
          } else {
            reader.read_content(form);
          }
        }
        files.push_back(entry);
      }
      headers->emplace_back(sec_offset, init_len, data_ptr, ptr + init_len, (DwarfVersion)version, addr_size,
                            min_ins_len, max_ops_per_ins, default_is_stmt, line_base, line_range, opcode_base,
                            opcode_lengths, std::move(dirs), std::move(files));
      reader.skip(init_len - reader.pop_bookmark());
    }
  }

  ASSERT(!reader.has_more(),
         ".debug_line section is expected to have been consumed here, but {} bytes were remaining",
         reader.remaining_size());
  return headers;
}

RelocatedLteIterator
SourceCodeFile::begin(AddrPtr relocatedBase) const noexcept
{
  // Rust would call this "interior" mutability. So kindly go fuck yourself.
  if (!is_computed()) {
    this->compute_line_tables();
  }
  return RelocatedLteIterator(line_table->begin(), relocatedBase);
}

RelocatedLteIterator
SourceCodeFile::end(AddrPtr relocatedBase) const noexcept
{
  return RelocatedLteIterator(line_table->end(), relocatedBase);
}

SourceCodeFile::SourceCodeFile(Elf *elf, std::filesystem::path path, std::vector<LNPHeader *> &&headers) noexcept
    : headers(std::move(headers)), line_table(std::make_shared<std::vector<LineTableEntry>>()), low(nullptr),
      high(nullptr), m(), computed(false), elf(elf), full_path(std::move(path))
{
}

auto
SourceCodeFile::first_linetable_entry(AddrPtr relocatedBase, u32 line, std::optional<u32> column)
  -> std::optional<LineTableEntry>
{
  auto lte_it = std::find_if(begin(relocatedBase), end(relocatedBase), [&](const auto &lte) {
    return line == lte.line && lte.column == column.value_or(lte.column);
  });
  if (lte_it != end(relocatedBase)) {
    return lte_it.get();
  } else {
    return std::nullopt;
  }
}

auto
SourceCodeFile::find_by_pc(AddrPtr base, AddrPtr addr) const noexcept -> std::optional<RelocatedLteIterator>
{
  auto start = begin(base);
  // might be a source code file with no line number info. e.g. include/stdio.h
  if (start == end(base)) {
    return std::nullopt;
  }
  if ((*start).pc == addr) {
    return start;
  }

  auto it = std::lower_bound(begin(base), end(base), addr,
                             [](const LineTableEntry &lte, AddrPtr pc) { return lte.pc < pc; });
  if (it == end(base)) {
    return std::nullopt;
  }

  return it;
}

void
SourceCodeFile::add_header(LNPHeader *header) noexcept
{
  if (std::ranges::none_of(headers, [header](auto h) { return h == header; })) {
    headers.push_back(header);
  }
}

AddressRange
SourceCodeFile::address_bounds() noexcept
{
  if (computed) {
    return AddressRange{low, high};
  }
  compute_line_tables();
  return AddressRange{low, high};
}

bool
SourceCodeFile::is_computed() const noexcept
{
  return computed;
}

void
SourceCodeFile::compute_line_tables() const noexcept
{
  std::lock_guard lock(m);
  if (computed) {
    return;
  }

  std::set<LineTableEntry> unique_ltes{};
  for (auto header : headers) {
    auto file_entry_index = header->file_entry_index(full_path);
    ASSERT(file_entry_index, "Expected a file entry index but did not find one");

    DBGLOG(dwarf, "[lnp]: computing lnp at 0x{:x}", header->sec_offset);
    using OpCode = LineNumberProgramOpCode;
    DwarfBinaryReader reader{elf, header->data, static_cast<u64>(header->data_end - header->data)};
    while (reader.has_more()) {
      SourceCodeFileLNPResolver state{header, unique_ltes, std::nullopt, file_entry_index.value()};
      while (reader.has_more() && !state.sequence_ended()) {
        const auto opcode = reader.read_value<OpCode>();
        if (const auto spec_op = std::to_underlying(opcode); spec_op >= header->opcode_base) {
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
            if (header->addr_size == 4) {
              const auto addr = reader.read_value<u32>();
              state.set_address(addr);
            } else {
              const auto addr = reader.read_value<u64>();
              state.set_address(addr);
            }
            break;
          case LineNumberProgramExtendedOpCode::DW_LNE_define_file: {
            if (header->version == DwarfVersion::D4) {
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
            while (reader.current_ptr() < end) {
              reader.read_value<u8>();
            }
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
  }
  auto &lt = *line_table;
  lt.reserve(unique_ltes.size());
  std::copy(std::begin(unique_ltes), std::end(unique_ltes), std::back_inserter(lt));
  ASSERT(std::is_sorted(lt.begin(), lt.end(), [](auto &a, auto &b) { return a.pc < b.pc; }),
         "Line Table was not sorted by Program Counter!");
  if (lt.size() > 2) {
    low = lt.front().pc;
    high = lt.back().pc;
  }
  computed = true;
}

RelocatedSourceCodeFile::RelocatedSourceCodeFile(AddrPtr base_addr,
                                                 std::shared_ptr<SourceCodeFile> src_file) noexcept
    : baseAddr(base_addr), file(*src_file)
{
}

RelocatedSourceCodeFile::RelocatedSourceCodeFile(AddrPtr base_addr, SourceCodeFile *src_file) noexcept
    : baseAddr(base_addr), file(*src_file)
{
}

auto
RelocatedSourceCodeFile::find_lte_by_pc(AddrPtr pc) const noexcept -> std::optional<RelocatedLteIterator>
{
  return file.find_by_pc(baseAddr, pc);
}

AddressRange
RelocatedSourceCodeFile::address_bounds() noexcept
{
  return AddressRange::relocate(file.address_bounds(), baseAddr);
}

} // namespace sym::dw