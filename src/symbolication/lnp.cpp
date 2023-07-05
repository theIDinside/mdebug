#include "lnp.h"
#include <variant>

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
read_content_str(DwarfBinaryReader &reader, AttributeForm form)
{
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return reader.read_string();
  case DW_FORM_line_strp:
  case DW_FORM_strp:
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

std::unique_ptr<LineHeader>
read_lineheader_v5(const u8 *ptr) noexcept
{
  DwarfBinaryReader reader{ptr, 4096};
  const auto init_len = reader.read_initial_length<DwarfBinaryReader::UpdateBufferSize>();
  const auto version = reader.read_value<u16>();
  const auto addr_size = reader.read_value<u8>();
  const auto segment_selector_size = reader.read_value<u8>();
  const u64 header_length = reader.dwarf_spec_read_value();
  const u8 *data_ptr = reader.current_ptr() + header_length;
  const u8 min_ins_len = reader.read_value<u8>();
  const u8 max_ops_per_ins = reader.read_value<u8>();
  const bool default_is_stmt = reader.read_value<u8>();
  const i8 line_base = reader.read_value<i8>();
  const u8 line_range = reader.read_value<u8>();
  const u8 opcode_base = reader.read_value<u8>();
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> opcode_lengths{};
  reader.read_into_array(opcode_lengths);

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
        ent.path = read_content_str(reader, form);
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
        entry.file_name = read_content_str(reader, form);
      } else {
        read_content(reader, form);
      }
    }
    files.push_back(entry);
  }

  return std::unique_ptr<LineHeader>(new LineHeader{.initial_length = init_len,
                                                    .data = data_ptr,
                                                    .data_length = reader.remaining_size(),
                                                    .version = (DwarfVersion)version,
                                                    .addr_size = addr_size,
                                                    .segment_selector_size = segment_selector_size,
                                                    .min_len = min_ins_len,
                                                    .max_ops = max_ops_per_ins,
                                                    .default_is_stmt = default_is_stmt,
                                                    .line_base = line_base,
                                                    .line_range = line_range,
                                                    .opcode_base = opcode_base,
                                                    .std_opcode_lengths = opcode_lengths,
                                                    .directories = std::move(dirs),
                                                    .file_names = std::move(files)});
}

std::unique_ptr<LineHeader>
read_lineheader_v4(const u8 *ptr, u8 addr_size) noexcept
{
  DwarfBinaryReader reader{ptr, 4096};
  // https://dwarfstd.org/doc/DWARF4.pdf#page=126
  const auto init_len = reader.read_initial_length<DwarfBinaryReader::UpdateBufferSize>();
  const auto lnp_for_cu_end = reader.current_ptr() + init_len;
  const auto version = reader.read_value<u16>();
  const u64 header_length = reader.dwarf_spec_read_value();
  const u8 *data_ptr = reader.current_ptr() + header_length;
  const auto data_len = static_cast<u64>(lnp_for_cu_end - data_ptr);
  const u8 min_ins_len = reader.read_value<u8>();
  const u8 max_ops_per_ins = reader.read_value<u8>();
  const bool default_is_stmt = reader.read_value<u8>();
  const i8 line_base = reader.read_value<i8>();
  const u8 line_range = reader.read_value<u8>();
  const u8 opcode_base = reader.read_value<u8>();
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> opcode_lengths{};
  reader.read_into_array(opcode_lengths);

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

  return std::unique_ptr<LineHeader>(new LineHeader{.initial_length = init_len,
                                                    .data = data_ptr,
                                                    .data_length = data_len,
                                                    .version = (DwarfVersion)version,
                                                    .addr_size = addr_size,
                                                    .segment_selector_size = 0,
                                                    .min_len = min_ins_len,
                                                    .max_ops = max_ops_per_ins,
                                                    .default_is_stmt = default_is_stmt,
                                                    .line_base = line_base,
                                                    .line_range = line_range,
                                                    .opcode_base = opcode_base,
                                                    .std_opcode_lengths = opcode_lengths,
                                                    .directories = std::move(dirs),
                                                    .file_names = std::move(files)});
}