/** LICENSE TEMPLATE */
#include "lnp.h"
#include "symbolication/block.h"
#include "utils/enumerator.h"
#include <filesystem>
#include <set>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <type_traits>
#include <utility>

namespace mdb::sym::dw {
using FileIndex = u32;

/*
  ASSERT(buildDirectory, "Expected build directory to not be null, p={}; lnp header=0x{:x}, object={}", p.c_str(),
         sec_offset, mObjectFile->GetObjectFileId());
*/

#define LNP_ASSERT(cond, formatString, ...)                                                                       \
  ASSERT((cond), "[object={}, lnp=0x{:x}]: " formatString, mObjectFile->GetFilePath().filename().c_str(),         \
         sec_offset __VA_OPT__(, ) __VA_ARGS__)

LNPHeader::LNPHeader(ObjectFile *object, u64 section_offset, u64 initial_length, const u8 *data,
                     const u8 *data_end, DwarfVersion version, u8 addr_size, u8 min_len, u8 max_ops,
                     bool default_is_stmt, i8 line_base, u8 line_range, u8 opcode_base,
                     OpCodeLengths opcode_lengths, std::vector<DirEntry> &&directories,
                     std::vector<FileEntry> &&file_names) noexcept
    : sec_offset(section_offset), initial_length(initial_length), data(data), data_end(data_end), version(version),
      addr_size(addr_size), min_len(min_len), max_ops(max_ops), default_is_stmt(default_is_stmt),
      line_base(line_base), line_range(line_range), opcode_base(opcode_base), mObjectFile(object),
      std_opcode_lengths(opcode_lengths), directories(std::move(directories)), mFileEntries(std::move(file_names))
{
}

LNPFilePath::LNPFilePath(Path &&path, u32 index)
    : mCanonicalPath(path.is_relative() ? path.lexically_normal() : std::move(path)), mIndex(index)
{
}

std::optional<Path>
LNPHeader::file(u32 f_index) const noexcept
{
  const auto adjusted_index = version == DwarfVersion::D4 ? (f_index == 0 ? 0 : f_index - 1) : f_index;
  if (adjusted_index >= mFileEntries.size()) {
    return {};
  }

  for (const auto &[i, f] : mdb::EnumerateView(mFileEntries)) {
    if (i == adjusted_index) {
      const auto dir_index = lnp_index(f.dir_index, version);
      return std::filesystem::path{fmt::format("{}/{}", directories[dir_index].path, f.file_name)}
        .lexically_normal();
    }
  }

  return std::nullopt;
}

Path
LNPHeader::CompileDirectoryJoin(const Path &p) const noexcept
{
  if (version == DwarfVersion::D5) {
    return (directories[0].path / p).lexically_normal();
  }
  LNP_ASSERT(mCompilationUnitBuildDirectory != nullptr, "Expected build directory to not be null, p={}",
             p.c_str());
  return (mCompilationUnitBuildDirectory / p).lexically_normal();
}

Path
LNPHeader::FileEntryToPath(const FileEntry &fileEntry) noexcept
{
  auto p = std::filesystem::path{fileEntry.file_name};
  if (p.is_relative()) {
    p = CompileDirectoryJoin(p);
  }
  LNP_ASSERT(p.is_absolute(), "No directories in LNP file paths must be absolute according to spec, but was={}",
             p.c_str());
  return p;
}

void
LNPHeader::CacheLNPFilePaths() noexcept
{
  if (!mFileToFileIndex.empty()) {
    return;
  }
  mFileToFileIndex.reserve(mFileEntries.size());
  std::string path_buf{};
  path_buf.reserve(1024);

  int fileIndex = 0;
  switch (version) {
  case DwarfVersion::D2:
  case DwarfVersion::D3:
  case DwarfVersion::D4:
    fileIndex = 1;
    break;
  case DwarfVersion::D5:
    break;
  }

  for (const auto &f : mFileEntries) {
    path_buf.clear();
    const auto index = lnp_index(f.dir_index, version);
    // this should be safe, because the string_views (which we call .data() on) are originally null-terminated
    // and we have not made copies.
    if (directories.empty()) {
      auto p = FileEntryToPath(f);
      mFileToFileIndex[p].Add(fileIndex);
    } else {
      std::string_view buildDir;
      if (std::to_underlying(version) < 5 && f.dir_index == 0) {
        LNP_ASSERT(mCompilationUnitBuildDirectory != nullptr, "Expected to have set build directory for LNP");
        buildDir = mCompilationUnitBuildDirectory;
      } else {
        buildDir = directories[index].path;
      }
      fmt::format_to(std::back_inserter(path_buf), "{}/{}", buildDir, f.file_name);
      auto p = std::filesystem::path{path_buf}.lexically_normal();
      if (p.is_relative()) {
        p = CompileDirectoryJoin(p);
      }

      mFileToFileIndex[p].Add(fileIndex);
    }
    fileIndex++;
  }
}

const LNPHeader::FileEntryContainer &
LNPHeader::FileEntries()
{
  LNP_ASSERT(!mFileEntries.empty(), "No file entries has been loaded");
  CacheLNPFilePaths();
  return mFileToFileIndex;
}

AddrPtr
LineTableEntry::RelocateProgramCounter(AddrPtr base) const noexcept
{
  return pc + base;
}

RelocatedLteIterator::RelocatedLteIterator(RelocatedLteIterator::Iter iter, AddrPtr base) noexcept
    : it(iter), base(base)
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

static LNPHeader *
ReadLineNumberProgramHeaderPreVersion4(DwarfBinaryReader &reader, ObjectFile *objectFile, u64 debugLineOffset,
                                       const u8 *ptr, u64 init_len, u16 version, u64 sec_offset) noexcept
{
  const u64 header_length = reader.dwarf_spec_read_value();
  const auto data_ptr = reader.current_ptr() + header_length;
  const u8 min_ins_len = reader.read_value<u8>();
  const u8 max_ops_per_ins = 1;
  const bool default_is_stmt = reader.read_value<u8>();
  const i8 line_base = reader.read_value<i8>();
  const u8 line_range = reader.read_value<u8>();
  const u8 opcode_base = reader.read_value<u8>();
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> opcode_lengths{};
  reader.read_into_array(opcode_lengths);

  const u8 addr_size = 8u;
  ASSERT(version == 2 || version == 3, "Incompatible version with reader: {}", version);
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
  auto header = new LNPHeader{
    objectFile,  sec_offset,     init_len,        data_ptr,        ptr + init_len, (DwarfVersion)version,
    addr_size,   min_ins_len,    max_ops_per_ins, default_is_stmt, line_base,      line_range,
    opcode_base, opcode_lengths, std::move(dirs), std::move(files)};
  // Another thread raced to complete it's parsing of this lnp header.
  if (!objectFile->SetLnpHeader(debugLineOffset, header)) {
    delete header;
    return objectFile->GetLnpHeader(debugLineOffset);
  }
  return header;
}

void
LNPHeader::SetCompilationUnitBuildDirectory(NonNullPtr<const char> string) noexcept
{
  mCompilationUnitBuildDirectory = string;
}

/* static */
LNPHeader *
LNPHeader::ReadLineNumberProgramHeader(ObjectFile *objectFile, u64 debugLineOffset) noexcept
{
  auto elf = objectFile->GetElf();
  if (objectFile->HasReadLnpHeader(debugLineOffset)) {
    return objectFile->GetLnpHeader(debugLineOffset);
  }
  ASSERT(elf != nullptr, "ELF must be parsed first");
  auto debug_line = elf->debug_line;
  ASSERT(debug_line != nullptr && debug_line->GetName() == ".debug_line", "Must pass .debug_line ELF section");
  // determine header count

  DwarfBinaryReader reader{elf, debug_line->mSectionData};
  reader.skip(debugLineOffset);

  u8 addr_size = 8u;
  const auto sec_offset = reader.bytes_read();
  const auto init_len = reader.read_initial_length<DwarfBinaryReader::Ignore>();
  const auto ptr = reader.current_ptr();
  reader.bookmark();
  const auto version = reader.peek_value<u16>();

  ASSERT(version < 6 && version >= 2,
         "WARNING: Line number program header of unsupported version: {} at offset 0x{:x}", version,
         reader.bytes_read());
  reader.skip_value<u16>();

  if (version == 5) {
    addr_size = reader.read_value<u8>();
    // don't care for segment selector size
    reader.skip(1);
  }

  if (version == 2 || version == 3) {
    return ReadLineNumberProgramHeaderPreVersion4(reader, objectFile, debugLineOffset, ptr, init_len, version,
                                                  sec_offset);
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

  if (version == 4 || version == 2) {
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
    auto header = new LNPHeader{
      objectFile,  sec_offset,     init_len,        data_ptr,        ptr + init_len, (DwarfVersion)version,
      addr_size,   min_ins_len,    max_ops_per_ins, default_is_stmt, line_base,      line_range,
      opcode_base, opcode_lengths, std::move(dirs), std::move(files)};
    // Another thread raced to complete it's parsing of this lnp header.
    if (!objectFile->SetLnpHeader(debugLineOffset, header)) {
      delete header;
      return objectFile->GetLnpHeader(debugLineOffset);
    }
    return header;
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
    auto header = new LNPHeader{
      objectFile,  sec_offset,     init_len,        data_ptr,        ptr + init_len, (DwarfVersion)version,
      addr_size,   min_ins_len,    max_ops_per_ins, default_is_stmt, line_base,      line_range,
      opcode_base, opcode_lengths, std::move(dirs), std::move(files)};

    // Another thread raced to complete it's parsing of this lnp header.
    if (!objectFile->SetLnpHeader(debugLineOffset, header)) {
      delete header;
      return objectFile->GetLnpHeader(debugLineOffset);
    }
    return header;
  }
}

std::vector<LNPHeader>
read_lnp_headers(ObjectFile *objectFile) noexcept
{
  auto elf = objectFile->GetElf();
  ASSERT(elf != nullptr, "ELF must be parsed first");
  auto debug_line = elf->debug_line;
  ASSERT(debug_line != nullptr && debug_line->GetName() == ".debug_line", "Must pass .debug_line ELF section");
  auto header_count = 0u;
  // determine header count
  {
    DwarfBinaryReader reader{elf, debug_line->mSectionData};
    while (reader.has_more()) {
      header_count++;
      const auto init_len = reader.read_initial_length<DwarfBinaryReader::Ignore>();
      reader.skip(init_len);
    }
  }

  std::vector<LNPHeader> headers{};
  headers.reserve(header_count);
  DwarfBinaryReader reader{elf, debug_line->mSectionData};

  u8 addr_size = 8u;
  for (auto i = 0u; i < header_count; ++i) {
    const auto sec_offset = reader.bytes_read();
    const auto init_len = reader.read_initial_length<DwarfBinaryReader::Ignore>();
    const auto ptr = reader.current_ptr();
    reader.bookmark();
    const auto version = reader.peek_value<u16>();
    switch (version) {
    case 1:
      [[fallthrough]];
    case 2:
      [[fallthrough]];
    case 3:
      [[fallthrough]];
    case 6:
      DBGLOG(core, "WARNING: Line number program header of unsupported version: {} at offset 0x{:x}", version,
             reader.bytes_read())
      reader.skip(init_len);
      continue;
    case 4:
      [[fallthrough]];
    case 5:
      reader.skip_value<u16>();
      break;
    default:
      ASSERT(version >= 1 && version <= 6, "Invalid DWARF version value encountered: {} at offset 0x{:x}", version,
             reader.bytes_read());
    }

    // TODO(simon): introduce release-build logging & warnings; this should not fail, but should log a
    // warning/error message on all builds
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
      headers.emplace_back(objectFile, sec_offset, init_len, data_ptr, ptr + init_len, (DwarfVersion)version,
                           addr_size, min_ins_len, max_ops_per_ins, default_is_stmt, line_base, line_range,
                           opcode_base, opcode_lengths, std::move(dirs), std::move(files));
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
      headers.emplace_back(objectFile, sec_offset, init_len, data_ptr, ptr + init_len, (DwarfVersion)version,
                           addr_size, min_ins_len, max_ops_per_ins, default_is_stmt, line_base, line_range,
                           opcode_base, opcode_lengths, std::move(dirs), std::move(files));
      reader.skip(init_len - reader.pop_bookmark());
    }
  }

  ASSERT(!reader.has_more(),
         ".debug_line section is expected to have been consumed here, but {} bytes were remaining",
         reader.remaining_size());
  return headers;
}

sym::CompilationUnit *
SourceCodeFile::GetOwningCompilationUnit() const noexcept
{
  return mCompilationUnit;
}

SourceCodeFile::SourceCodeFile(sym::CompilationUnit *compilationUnit, const Elf *elf, std::filesystem::path &&path,
                               FileEntryIndexVector fileIndices) noexcept
    : mCompilationUnit(compilationUnit), elf(elf), mLineInfoFileIndices(fileIndices), mFullPath(std::move(path))
{
}

/* static */
SourceCodeFile::Ref
SourceCodeFile::Create(sym::CompilationUnit *compilationUnit, const Elf *elf, std::string path,
                       FileEntryIndexVector fileIndices) noexcept
{
  return std::shared_ptr<SourceCodeFile>(new SourceCodeFile{compilationUnit, elf, std::move(path), fileIndices});
}

AddressRange
SourceCodeFile::address_bounds() noexcept
{
  if (IsComputed()) {
    return mSpan;
  }
  ComputeLineTableForThis();
  return mSpan;
}

bool
SourceCodeFile::HasAddressRange() noexcept
{
  auto range = address_bounds();

  return range.IsValid();
}

void
SourceCodeFile::AddLineTableRanges(const std::vector<std::pair<u32, u32>> &ranges) noexcept
{
  for (const auto [start, end] : ranges) {
    mLineTableRanges.push_back({start, end});
  }
}

void
SourceCodeFile::ReadInSourceCodeLineTable(std::vector<LineTableEntry> &result) noexcept
{
  if (!IsComputed()) {
    ComputeLineTableForThis();
  }
  u32 acc = 0;

  for (auto r : mLineTableRanges) {
    acc += r.Count();
  }
  // We add sentinel line table entries.
  // This is for cases where a source code file have 1 line table entry in the compilation unit line table
  // Why you ask? Take a look at this:
  //      Address         Line   Column    File
  // 0x0000000004416230     16      0      1      0             0       0  is_stmt
  // 0x000000000441623a    256     58      5      0             0       0  is_stmt prologue_end
  // 0x0000000004416241     16      7      1      0             0       0  is_stmt
  // Imagine a situation where between addresses 0x441623a and 0x4416241 there are multiple instructions
  // Do they belong to file 1 or file 5? It's *probably* the case that it belongs to 5, right?
  // Right, the thing is, in the read in line table for this source code file, store in the param `result`
  // we may insert the 2nd entry here, and then another entry, much later, and that *could* make it seem as
  // though this 2nd entry and that far removed entry span the entire range between those two. That would be
  // wrong. This was actually the reason for decision to re-factor the source code files to not be unique and
  // contain all line table ranges, and instead duplicate those, to map 1-to-1 with dwarf information, which
  // means that foo.h can be defined in multiple places in the debug symbol information Also, by keeping the
  // original line number program table for the entire compilation unit, makes it binary-searchable which is much
  // prefered over scanning.

  result.reserve(acc + (mLineTableRanges.size() * 2));

  auto lineTable = mCompilationUnit->GetLineTable();
  auto it = std::back_inserter(result);
  for (const auto &r : mLineTableRanges) {
    auto subspan = lineTable.subspan(r.mStartIndex, r.Count());
    it = std::copy(std::begin(subspan), std::end(subspan), it);
    const auto end = r.mStartIndex + r.Count();
    if (lineTable.size() > end) {
      result.push_back(lineTable[end]);
      // we manufacture this line table entry on the fly, by changing it into an "end_sequence"
      // entry, even though, in the actual line table it may not be one. But for this source code file, it will
      // be. result.back().file may actually be pointing to a completely different file, but it makes it possible
      // for us to say, if the pc is between result[size-2].pc and result[size-1].pc, we're probably on the line
      // of result[size-1].line
      result.back().IsEndOfSequence = true;
    }
  }
}

bool
SourceCodeFile::IsComputed() const noexcept
{
  return mCompilationUnit->LineTableComputed();
}

void
SourceCodeFile::ComputeLineTableForThis() noexcept
{
  mCompilationUnit->ComputeLineTable();
}

} // namespace mdb::sym::dw