/** LICENSE TEMPLATE */
// mdb
#include <common/panic.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <utils/logger.h>
namespace mdb {
u64
DwarfBinaryReader::DwarfSpecReadValue() noexcept
{
  switch (mOffsetSize) {
  case 4:
    return ReadValue<u32>();
  case 8:
    return ReadValue<u64>();
  default:
    PANIC(fmt::format("Unsupported offset size {}", mOffsetSize));
  }
}

std::span<const u8>
DwarfBinaryReader::GetSpan(u64 size) noexcept
{
  ASSERT(size <= RemainingSize(), "Not enough bytes left in reader. Requested {}, remaining {}", size,
         RemainingSize());
  const auto span = std::span{mHead, size};
  mHead += size;
  return span;
}

std::string_view
DwarfBinaryReader::ReadString() noexcept
{
  std::string_view str{(const char *)(mHead)};
  mHead += str.size() + 1;
  return str;
}

void
DwarfBinaryReader::SkipString() noexcept
{
  std::string_view str{(const char *)(mHead)};
  mHead += str.size() + 1;
}

DataBlock
DwarfBinaryReader::ReadBlock(u64 size) noexcept
{
  const auto ptr = mHead;
  mHead += size;
  return {.ptr = ptr, .size = size};
}

u64
DwarfBinaryReader::ReadOffset() noexcept
{
  switch (mOffsetSize) {
  case 8:
    return ReadValue<u64>();
  case 4:
    return ReadValue<u32>();
  default:
    TODO_FMT("Reading offsets/addresses of size {} not yet supported", mOffsetSize);
  }
}

const u8 *
DwarfBinaryReader::CurrentPtr() const noexcept
{
  return mHead;
}

DwarfBinaryReader::DwarfBinaryReader(std::span<const u8> data) noexcept
    : DwarfBinaryReader(nullptr, data.data(), data.size())
{
}

DwarfBinaryReader::DwarfBinaryReader(const Elf *elf, const u8 *buffer, u64 size) noexcept
    : mBuffer(buffer), mHead(buffer), mEnd(buffer + size), mSize(size), mBookmarks(), mElf(elf)
{
}

DwarfBinaryReader::DwarfBinaryReader(const Elf *elf, std::span<const u8> data) noexcept
    : mBuffer(data.data()), mHead(data.data()), mEnd(mBuffer + data.size()), mBookmarks(), mElf(elf)
{
}

DwarfBinaryReader::DwarfBinaryReader(const DwarfBinaryReader &reader) noexcept
    : mBuffer(reader.mBuffer), mHead(reader.mHead), mEnd(reader.mEnd), mSize(reader.mSize),
      mBookmarks(reader.mBookmarks), mElf(reader.mElf)
{
}

bool
DwarfBinaryReader::HasMore() noexcept
{
  return mHead < mEnd;
}

u64
DwarfBinaryReader::RemainingSize() const noexcept
{
  return (mEnd - mHead);
}

u64
DwarfBinaryReader::BytesRead() const noexcept
{
  return mHead - mBuffer;
}

void
DwarfBinaryReader::Skip(i64 bytes) noexcept
{
  ASSERT(static_cast<u64>(bytes) <= RemainingSize() && mHead + bytes >= mBuffer,
         "Can't skip outside of buffer. Requested {}, remaining size: {}", bytes, RemainingSize());
  mHead += bytes;
}

void
DwarfBinaryReader::Bookmark() noexcept
{
  mBookmarks.push_back(BytesRead());
}

u64
DwarfBinaryReader::PopBookmark() noexcept
{
  const auto bookmark = mBookmarks.back();
  mBookmarks.pop_back();
  return BytesRead() - bookmark;
}

DwarfBinaryReader
SubReader(const DwarfBinaryReader &reader) noexcept
{
  return DwarfBinaryReader{reader.mElf, reader.mHead, reader.mSize - (reader.mHead - reader.mBuffer)};
}

u64
DwarfBinaryReader::ReadContentIndex(AttributeForm form) noexcept
{
  ASSERT(mElf != nullptr, "No ELF passed to this binary reader");
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_udata:
    return ReadUleb128<u64>();
  case DW_FORM_data1:
    return ReadValue<u8>();
  case DW_FORM_data2:
    return ReadValue<u16>();
  default:
    PANIC(fmt::format("Unsupported form for dir index {}", to_str(form)));
  }
}

std::string_view
DwarfBinaryReader::ReadContentStr(AttributeForm form) noexcept
{
  ASSERT(mElf != nullptr, "No ELF passed to this binary reader");
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return ReadString();
  case DW_FORM_line_strp:
    ASSERT(mElf->mDebugLineStr != nullptr, "Reading value of form DW_FORM_line_strp requires .debug_line section");
    return mElf->mDebugLineStr->GetCString(ReadOffset());
  case DW_FORM_strp:
    ASSERT(mElf->mDebugStr != nullptr, "Reading value of form DW_FORM_strp requires .debug_str section");
    return mElf->mDebugStr->GetCString(ReadOffset());
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
DwarfBinaryReader::ReadContentDatablock(AttributeForm form) noexcept
{
  ASSERT(mElf != nullptr, "No ELF passed to this binary reader");
  switch (form) {
  case AttributeForm::DW_FORM_data16:
    return ReadBlock(16);
  case AttributeForm::DW_FORM_block: {
    const auto sz = ReadUleb128<u64>();
    return ReadBlock(sz);
  }
  default:
    PANIC(fmt::format("Unsupported block form {}", to_str(form)));
  }
}

std::variant<std::string_view, u64, DataBlock>
DwarfBinaryReader::ReadContent(AttributeForm form) noexcept
{
  ASSERT(mElf != nullptr, "No ELF passed to this binary reader");
  using enum AttributeForm;
  switch (form) {
  case DW_FORM_string:
    return ReadString();
  case DW_FORM_line_strp:
    [[fallthrough]];
  case DW_FORM_strp:
    [[fallthrough]];
  case DW_FORM_strp_sup:
    return DwarfSpecReadValue();
  case DW_FORM_udata:
    return ReadUleb128<u64>();
  case DW_FORM_data1:
    return ReadValue<u8>();
  case DW_FORM_data2:
    return ReadValue<u16>();
  case DW_FORM_data4:
    return ReadValue<u32>();
  case DW_FORM_data8:
    return ReadValue<u64>();
  case DW_FORM_data16:
    return ReadBlock(16);
  case DW_FORM_block: {
    const auto sz = ReadUleb128<u64>();
    return ReadBlock(sz);
  }
  default:
    PANIC(fmt::format("Unacceptable form {} while reading LNP content description", to_str(form)));
  }
}

void
DwarfBinaryReader::SetWrappedBufferSize(u64 new_size) noexcept
{
  mEnd = mBuffer + new_size;
  mSize = new_size;
}
} // namespace mdb