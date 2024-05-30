#pragma once
#include "../dwarf_defs.h"
#include "symbolication/block.h"
#include "utils/immutable.h"
#include <common.h>

class Elf;

namespace sym::dw {
struct DirEntry
{
  std::string_view path;
  std::optional<DataBlock> md5;
};

constexpr u64
lnp_index(u64 index, DwarfVersion version) noexcept
{
  if (version == DwarfVersion::D4) {
    if (index == 0) {
      return index;
    } else {
      return index - 1;
    }
  }
  return index;
}

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
  NO_COPY_DEFAULTED_MOVE(LNPHeader);
  using shr_ptr = std::shared_ptr<LNPHeader>;
  using OpCodeLengths = std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)>;
  using DirEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  using FileNameEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  LNPHeader(u64 section_offset, u64 initial_length, const u8 *data, const u8 *data_end, DwarfVersion version,
            u8 addr_size, u8 min_len, u8 max_ops, bool default_is_stmt, i8 line_base, u8 line_range,
            u8 opcode_base, OpCodeLengths opcode_lengths, std::vector<DirEntry> &&directories,
            std::vector<FileEntry> &&file_names) noexcept;

  std::vector<std::filesystem::path> files() const noexcept;
  std::optional<Path> file(u32 index) const noexcept;
  std::optional<u32> file_entry_index(const std::filesystem::path &p) const noexcept;

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

  friend auto
  operator<=>(const LineTableEntry &l, const LineTableEntry &r) noexcept
  {
    return l.pc.get() <=> r.pc.get();
  }
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

  RelocatedLteIterator operator+(difference_type diff) const noexcept;
  RelocatedLteIterator operator-(difference_type diff) const noexcept;
  difference_type operator-(RelocatedLteIterator diff) const noexcept;

  RelocatedLteIterator &operator+=(difference_type diff) noexcept;
  RelocatedLteIterator &operator-=(difference_type diff) noexcept;
  RelocatedLteIterator &operator++() noexcept;
  RelocatedLteIterator operator++(int) noexcept;
  RelocatedLteIterator &operator--() noexcept;
  RelocatedLteIterator operator--(int) noexcept;

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

class RelocatedSourceCodeFile;

// A source code file is a file that's either represented (and thus realized, when parsed) in the Line Number
// Program or referenced somehow from an actual Compilation Unit/Translation unit; Meaning, DWARF does not
// represent it as a single, solitary "binary blob" of debug symbol info. Something which generally tend to only be
// "source code file" (Our own, Midas definition for it) are header files which can be included in many different
// s files. This is generally true for templated code, for instance. A `SourceCodeFile` does not "own" any
// particular
// debug info metadata that responsibility is left to a `SourceFileSymbolInfo`. I guess, GDB also makes a sort of
// similar distinction with it's "symtabs" and "psymtabs" - I guess?

class SourceCodeFile
{
public:
  NO_COPY(SourceCodeFile);
  friend RelocatedSourceCodeFile;

private:
  std::vector<LNPHeader *> headers;
  // Resolved lazily when needed, by walking `line_table`
  mutable SharedPtr<std::vector<LineTableEntry>> line_table;
  mutable AddrPtr low;
  mutable AddrPtr high;
  mutable std::mutex m;
  mutable bool computed;
  Elf *elf;
  bool is_computed() const noexcept;
  void compute_line_tables() const noexcept;

public:
  SourceCodeFile(Elf *elf, std::filesystem::path path, std::vector<LNPHeader *> &&headers) noexcept;
  Immutable<std::filesystem::path> full_path;

  auto begin(AddrPtr relocatedBase) const noexcept -> RelocatedLteIterator;
  auto end(AddrPtr relocatedBase) const noexcept -> RelocatedLteIterator;

  auto first_linetable_entry(AddrPtr relocatedBase, u32 line, std::optional<u32> column)
    -> std::optional<LineTableEntry>;

  auto find_by_pc(AddrPtr base, AddrPtr pc) const noexcept -> std::optional<RelocatedLteIterator>;
  auto add_header(LNPHeader *header) noexcept -> void;
  auto address_bounds() noexcept -> AddressRange;
};

// RelocatedFoo types are "thin" wrappers around the "raw" debug symbol info data types. This is so that we can
// potentially reused previously parsed debug data between different processes that we are debugging. I'm not
// entirely sure, we need this in the year of 2024, but I figured for good measure, let's not even allow for the
// possibility to duplicate work (when multi-process debugging)
class RelocatedSourceCodeFile
{
  Immutable<AddrPtr> baseAddr;
  SourceCodeFile &file;

public:
  RelocatedSourceCodeFile(AddrPtr base_addr, std::shared_ptr<SourceCodeFile> file) noexcept;
  RelocatedSourceCodeFile(AddrPtr base_addr, SourceCodeFile *file) noexcept;

  auto find_lte_by_pc(AddrPtr pc) const noexcept -> std::optional<RelocatedLteIterator>;
  auto address_bounds() noexcept -> AddressRange;

  auto
  path() const noexcept -> Path
  {
    return file.full_path;
  }

  constexpr friend auto
  operator<=>(const RelocatedSourceCodeFile &l, const RelocatedSourceCodeFile &r) noexcept
  {
    return &l.file <=> &r.file;
  }

  constexpr friend auto
  operator==(const RelocatedSourceCodeFile &l, const RelocatedSourceCodeFile &r) noexcept
  {
    return &l.file == &r.file;
  }

  SourceCodeFile &
  get() const noexcept
  {
    return file;
  }
};

std::shared_ptr<std::vector<LNPHeader>> read_lnp_headers(const Elf *elf) noexcept;
void compute_line_number_program(ParsedLineTableEntries &output, const Elf *elf, LNPHeader *header);
} // namespace sym::dw
