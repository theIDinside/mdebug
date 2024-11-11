#include "dwarf_binary_reader.h"
#include "elf.h"

u64
DwarfBinaryReader::dwarf_spec_read_value() noexcept
{
  switch (offset_size) {
  case 4:
    return read_value<u32>();
  case 8:
    return read_value<u64>();
  default:
    PANIC(fmt::format("Unsupported offset size {}", offset_size));
  }
}

std::span<const u8>
DwarfBinaryReader::get_span(u64 size) noexcept
{
  ASSERT(size <= remaining_size(), "Not enough bytes left in reader. Requested {}, remaining {}", size,
         remaining_size());
  const auto span = std::span{head, size};
  head += size;
  return span;
}

std::string_view
DwarfBinaryReader::read_string() noexcept
{
  std::string_view str{(const char *)(head)};
  head += str.size() + 1;
  return str;
}

void
DwarfBinaryReader::skip_string() noexcept
{
  std::string_view str{(const char *)(head)};
  head += str.size() + 1;
}

DataBlock
DwarfBinaryReader::read_block(u64 size) noexcept
{
  const auto ptr = head;
  head += size;
  return {.ptr = ptr, .size = size};
}

u64
DwarfBinaryReader::read_offset() noexcept
{
  switch (offset_size) {
  case 8:
    return read_value<u64>();
  case 4:
    return read_value<u32>();
  default:
    TODO_FMT("Reading offsets/addresses of size {} not yet supported", offset_size);
  }
}

const u8 *
DwarfBinaryReader::current_ptr() const noexcept
{
  return head;
}

DwarfBinaryReader::DwarfBinaryReader(std::span<const u8> data) noexcept
    : DwarfBinaryReader(nullptr, data.data(), data.size())
{
}

DwarfBinaryReader::DwarfBinaryReader(const Elf *elf, const u8 *buffer, u64 size) noexcept
    : buffer(buffer), head(buffer), end(buffer + size), size(size), bookmarks(), elf(elf)
{
}

DwarfBinaryReader::DwarfBinaryReader(const DwarfBinaryReader &reader) noexcept
    : buffer(reader.buffer), head(reader.head), end(reader.end), size(reader.size), bookmarks(reader.bookmarks),
      elf(reader.elf)
{
}

bool
DwarfBinaryReader::has_more() noexcept
{
  return head < end;
}

u64
DwarfBinaryReader::remaining_size() const noexcept
{
  return (end - head);
}

u64
DwarfBinaryReader::bytes_read() const noexcept
{
  return head - buffer;
}

void
DwarfBinaryReader::skip(i64 bytes) noexcept
{
  ASSERT(static_cast<u64>(bytes) <= remaining_size() && head + bytes > buffer,
         "Can't skip outside of buffer. Requested {}, remaining size: {}", bytes, remaining_size());
  head += bytes;
}

void
DwarfBinaryReader::bookmark() noexcept
{
  bookmarks.push_back(bytes_read());
}

u64
DwarfBinaryReader::pop_bookmark() noexcept
{
  const auto bookmark = bookmarks.back();
  bookmarks.pop_back();
  return bytes_read() - bookmark;
}

DwarfBinaryReader
sub_reader(const DwarfBinaryReader &reader) noexcept
{
  return DwarfBinaryReader{reader.elf, reader.head, reader.size - (reader.head - reader.buffer)};
}

u64
DwarfBinaryReader::read_content_index(AttributeForm form) noexcept
{
  ASSERT(elf != nullptr, "No ELF passed to this binary reader");
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_udata:
    return read_uleb128<u64>();
  case DW_FORM_data1:
    return read_value<u8>();
  case DW_FORM_data2:
    return read_value<u16>();
  default:
    PANIC(fmt::format("Unsupported form for dir index {}", to_str(form)));
  }
}

std::string_view
DwarfBinaryReader::read_content_str(AttributeForm form) noexcept
{
  ASSERT(elf != nullptr, "No ELF passed to this binary reader");
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return read_string();
  case DW_FORM_line_strp:
    ASSERT(elf->debug_line_str != nullptr, "Reading value of form DW_FORM_line_strp requires .debug_line section");
    return std::string_view{(const char *)elf->debug_line_str->offset(read_offset())};
  case DW_FORM_strp:
    ASSERT(elf->debug_str != nullptr, "Reading value of form DW_FORM_strp requires .debug_str section");
    return std::string_view{(const char *)elf->debug_str->offset(read_offset())};
  case DW_FORM_strp_sup:
  case DW_FORM_strx:
  case DW_FORM_strx1:
  case DW_FORM_strx2:
  case DW_FORM_strx3:
  case DW_FORM_strx4:
  default:
    PANIC(fmt::format("Reading string of form {} not yet supported", to_str(form)));
  }
}

DataBlock
DwarfBinaryReader::read_content_datablock(AttributeForm form) noexcept
{
  ASSERT(elf != nullptr, "No ELF passed to this binary reader");
  switch (form) {
  case AttributeForm::DW_FORM_data16:
    return read_block(16);
  case AttributeForm::DW_FORM_block: {
    const auto sz = read_uleb128<u64>();
    return read_block(sz);
  }
  default:
    PANIC(fmt::format("Unsupported block form {}", to_str(form)));
  }
}

std::variant<std::string_view, u64, DataBlock>
DwarfBinaryReader::read_content(AttributeForm form) noexcept
{
  ASSERT(elf != nullptr, "No ELF passed to this binary reader");
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return read_string();
  case DW_FORM_line_strp:
    [[fallthrough]];
  case DW_FORM_strp:
    [[fallthrough]];
  case DW_FORM_strp_sup:
    return dwarf_spec_read_value();
  case DW_FORM_udata:
    return read_uleb128<u64>();
  case DW_FORM_data1:
    return read_value<u8>();
  case DW_FORM_data2:
    return read_value<u16>();
  case DW_FORM_data4:
    return read_value<u32>();
  case DW_FORM_data8:
    return read_value<u64>();
  case DW_FORM_data16:
    return read_block(16);
  case DW_FORM_block: {
    const auto sz = read_uleb128<u64>();
    return read_block(sz);
  }
  default:
    PANIC(fmt::format("Unacceptable form {} while reading LNP content description", to_str(form)));
  }
}

void
DwarfBinaryReader::set_wrapped_buffer_size(u64 new_size) noexcept
{
  end = buffer + new_size;
  size = new_size;
}