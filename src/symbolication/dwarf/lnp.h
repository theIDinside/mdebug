#pragma once
#include "../../common.h"
#include "../dwarf_defs.h"
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
  using DirEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  using FileNameEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
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
  LineTableEntry operator->();
  auto &operator+=(difference_type diff);
  auto &operator-=(difference_type diff);
  auto &operator++();
  auto operator++(int);
  auto &operator--();
  auto operator--(int);

  friend bool operator==(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator!=(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator<(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator>(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator<=(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
  friend bool operator>=(const RelocatedLteIterator &l, const RelocatedLteIterator &r);
};

class LineTable
{
public:
  LineTable(LNPHeader *header, std::shared_ptr<ParsedLineTableEntries> ltes, AddrPtr relocated_base) noexcept;

  RelocatedLteIterator begin() const;
  RelocatedLteIterator end() const;

private:
  AddrPtr relocated_base;
  LNPHeader *line_header;
  std::shared_ptr<ParsedLineTableEntries> ltes;
};

std::vector<LNPHeader> parse_lnp_headers(const Elf *elf) noexcept;
std::shared_ptr<ParsedLineTableEntries> compute_line_number_program(const LNPHeader *header);
} // namespace sym::dw
