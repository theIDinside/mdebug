#pragma once
#include "../common.h"
#include "dwarf_defs.h"
#include <optional>
#include <utility>

/**
 * LNP V4
 */
// unit_length                          4/12 bytes
// version                              2 bytes
// header_length                        4/8 bytes     - number of bytes, starting from `min_ins_len` to where data
// begins min_ins_len                          1 byte maximum_operations_per_instruction   1 byte default_is_stmt
// 1 byte line_base                            1 signed byte line_range                           1 byte
// opcode_base                          1 byte
// standard_opcode_lengths              (array of byte)
// include_directories                  (array of sequence of bytes (as string))
// file_names                           (array of sequence of bytes (as string))

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
};

/**
 * The processed Line Number Program Header. For the raw byte-to-byte representation see LineHeader4/5
 */
struct LineHeader
{
  using DirEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  using FileNameEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  u64 length;
  const u8 *data;
  DwarfVersion version;
  u8 addr_size;
  u8 segment_selector_size;
  u8 min_ins_length4;
  u8 max_ops_per_ins;
  bool default_is_stmt;
  i8 line_base;
  u8 line_range;
  u8 opcode_base;
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> std_opcode_lengths;
  std::vector<DirEntry> directories;
  std::vector<FileEntry> file_names;
};

std::unique_ptr<LineHeader> read_lineheader_v5(const u8 *bytes) noexcept;
std::unique_ptr<LineHeader> read_lineheader_v4(const u8 *ptr, u8 addr_size) noexcept;