#pragma once
#include "../block.h"
#include "dwarf_defs.h"
#include <common.h>
#include <optional>
#include <utility>

namespace sym {
class Elf;
struct ElfSection;
} // namespace sym

// SYMBOLS DWARF namespace
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
 * @brief Line Table Entry relates information between source code
 * locations and actual machine addresses. This is pretty hacky, the way
 * it's laid out in memory, but there's going to be a *lot* of these. A lot, lot.
 * Therefore, being able to keep it down to 16 bytes, instead of say, 24 or 32,
 * mean that when we parse millions of them, we save many megabytes; and there are additional benefits beyond that,
 * obviously, cache-friendliness. But that is just speculation right now, I have not benchmarked it.
 *
 */
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

struct LineTableEntryRange
{
  const LineTableEntry *begin;
  const LineTableEntry *end;
};
using LineTable = std::vector<LineTableEntry>;
using OwnedLineTable = std::unique_ptr<LineTable>;

/**
 * The processed Line Number Program Header. For the raw byte-to-byte representation see LineHeader4/5
 */
struct LineHeader
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
  LineTable *line_table;

  void parse_linetable(AddrPtr reloc_base, std::optional<AddressRange> bounds) noexcept;
  void set_linetable_storage(LineTable *storage) noexcept;
  DwarfBinaryReader get_reader() const noexcept;
  bool has_entries() const noexcept;
};

std::vector<LineHeader> parse_lnp_headers(const sym::Elf *) noexcept;

}; // namespace sym::dw

namespace fmt {
using LTE = sym::dw::LineTableEntry;
template <> struct formatter<LTE>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const LTE &entry, FormatContext &ctx)
  {
    return fmt::format_to(
        ctx.out(),
        " pc: 0x{:010x}, line: {:>4}, col: {:>4}, file: {:>3}, stmt: {:>5}, pe: {:>5}, basic block: "
        "{:>5}, epi end: {}",
        entry.pc.get(), entry.line, entry.column, entry.file, entry.is_stmt, entry.prologue_end, entry.basic_block,
        entry.epilogue_begin);
  }
};
} // namespace fmt