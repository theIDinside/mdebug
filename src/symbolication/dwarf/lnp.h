#pragma once
#include "../dwarf_defs.h"
#include <common.h>
#include <optional>

class Elf;

namespace sym::dw {
struct DirEntry
{
  std::string_view path;
  std::optional<DataBlock> md5;
};

struct FileEntry
{
  std::string_view file_name;
  u64 dir_index;
  std::optional<u64> file_size;
  std::optional<DataBlock> md5;
  std::optional<u64> last_modified;
};
/**
 * The processed Line Number Program Header. For the raw byte-to-byte representation see LineHeader4/5
 */
struct LNPHeader
{
  using shr_ptr = std::shared_ptr<LNPHeader>;
  using OpCodeLengths = std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)>;
  using DirEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  using FileNameEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  LNPHeader(u64 section_offset, u64 initial_length, const u8 *data, const u8 *data_end, DwarfVersion version,
            u8 addr_size, u8 min_len, u8 max_ops, bool default_is_stmt, i8 line_base, u8 line_range,
            u8 opcode_base, OpCodeLengths opcode_lengths, std::vector<DirEntry> &&directories,
            std::vector<FileEntry> &&file_names) noexcept;
  u64 sec_offset;
  u64 initial_length;
  const u8 *data;
  const u8 *data_end;
  DwarfVersion version;
  u8 addr_size;
  u8 min_len;
  u8 max_ops;
  bool default_is_stmt;
  i8 line_base;
  u8 line_range;
  u8 opcode_base;
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> std_opcode_lengths;
  std::vector<DirEntry> directories;
  std::vector<FileEntry> file_names;
};

struct LineTableEntry
{
  AddrPtr pc;
  u32 line;
  u32 column : 17;
  u16 file : 10;
  bool is_stmt : 1;
  bool prologue_end : 1;
  bool basic_block : 1;
  bool epilogue_begin : 1;
};

struct ParsedLineTableEntries
{
  using shr_ptr = std::shared_ptr<ParsedLineTableEntries>;
  std::vector<LineTableEntry> table;
};

struct RelocatedLteIterator
{
  using Iter = std::vector<LineTableEntry>::const_iterator;

private:
  Iter it;
  AddrPtr base;

public:
  using iterator_category = std::random_access_iterator_tag;
  using difference_type = std::ptrdiff_t;
  using value_type = LineTableEntry;
  using pointer = LineTableEntry *;
  using reference = LineTableEntry &;
  RelocatedLteIterator(Iter iter, AddrPtr base) noexcept;

  LineTableEntry operator*();
  LineTableEntry get() const noexcept;

  RelocatedLteIterator operator+(difference_type diff);
  RelocatedLteIterator operator-(difference_type diff);
  difference_type operator-(RelocatedLteIterator diff);

  RelocatedLteIterator &operator+=(difference_type diff);
  RelocatedLteIterator &operator-=(difference_type diff);
  RelocatedLteIterator &operator++();
  RelocatedLteIterator operator++(int);
  RelocatedLteIterator &operator--();
  RelocatedLteIterator operator--(int);

  friend bool operator==(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator!=(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator<(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator>(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator<=(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator>=(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
};

/**
 * LineTable is a light weight "handle" class and owns no data of it's own. It connects a line number program
 * header with the parsed line table entries from that line number program. This is, so that when we finally get to
 * multi process debugging two processes with the same object file(s) can share that parsed data and only alter the
 * small/cheap bits (like base address, or what we call relocated_base).
 */
class LineTable
{
public:
  LineTable() noexcept;
  LineTable(LNPHeader *header, ParsedLineTableEntries *ltes, AddrPtr relocated_base) noexcept;

  bool is_valid() const noexcept;

  RelocatedLteIterator begin() const noexcept;
  RelocatedLteIterator end() const noexcept;

  LineTableEntry front() const noexcept;
  LineTableEntry back() const noexcept;

  bool no_entries() const noexcept;
  u64 table_id() const noexcept;

  std::optional<sym::dw::DirEntry> directory(u64 dir_index) const noexcept;
  std::optional<sym::dw::FileEntry> file(u64 file_index) const noexcept;
  RelocatedLteIterator find_by_pc(AddrPtr addr) noexcept;
  u64 size() const noexcept;

private:
  AddrPtr relocated_base;
  LNPHeader *line_header;
  ParsedLineTableEntries *ltes;
};

std::shared_ptr<std::vector<LNPHeader>> read_lnp_headers(const Elf *elf) noexcept;
ParsedLineTableEntries compute_line_number_program(const Elf *elf, LNPHeader *header);
} // namespace sym::dw
