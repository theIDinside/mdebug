#include "lnp.h"
#include "../dwarf_binary_reader.h"
#include "../elf.h"

namespace sym::dw {

RelocatedLteIterator::RelocatedLteIterator(RelocatedLteIterator::Iter iter, AddrPtr base) noexcept
    : it(iter), base(base)
{
}

RelocatedLteIterator
LineTable::begin() const
{
  return RelocatedLteIterator(ltes->table.cbegin(), relocated_base);
}

RelocatedLteIterator
LineTable::end() const
{
  return RelocatedLteIterator(ltes->table.cend(), relocated_base);
}

LineTable::LineTable(LNPHeader *header, std::shared_ptr<ParsedLineTableEntries> ltes,
                     AddrPtr relocated_base) noexcept
    : relocated_base(relocated_base), line_header(header), ltes(ltes)
{
}

LineTableEntry
RelocatedLteIterator::operator*()
{
  auto lte = *it;
  lte.pc += base.get();
  return lte;
}

LineTableEntry
RelocatedLteIterator::operator->()
{
  auto lte = *it;
  lte.pc += base.get();
  return lte;
}

auto &
RelocatedLteIterator::operator+=(difference_type diff)
{
  it += diff;
  return *this;
}

auto &
RelocatedLteIterator::operator-=(difference_type diff)
{
  it -= diff;
  return *this;
}

auto &
RelocatedLteIterator::operator++()
{
  ++it;
  return *this;
}

auto
RelocatedLteIterator::operator++(int)
{
  auto copy = *this;
  ++copy.it;
  return copy;
}

auto &
RelocatedLteIterator::operator--()
{
  --it;
  return *this;
}

auto
RelocatedLteIterator::operator--(int)
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

std::shared_ptr<ParsedLineTableEntries>
compute_line_number_program(const LNPHeader *header)
{
  TODO("NOT IMPLEMENTED: std::shared_ptr<ParsedLineTableEntries> parse_line_number_program(const LNPHeader "
       "*header)");
}

std::vector<LNPHeader>
parse_lnp_headers(const Elf *elf) noexcept
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

  std::vector<LNPHeader> headers{};
  headers.reserve(header_count);
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
      headers.push_back(LNPHeader{.sec_offset = sec_offset,
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
                                  .file_names = std::move(files)});
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
      headers.push_back(LNPHeader{.sec_offset = sec_offset,
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
                                  .file_names = std::move(files)});
      reader.skip(init_len - reader.pop_bookmark());
    }
  }
  DLOG("dwarf", "[lnp]: parsed {} headers", headers.size());
  ASSERT(!reader.has_more(),
         ".debug_line section is expected to have been consumed here, but {} bytes were remaining",
         reader.remaining_size());
  return headers;
}

} // namespace sym::dw