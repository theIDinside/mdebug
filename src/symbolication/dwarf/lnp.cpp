#include "lnp.h"
#include "symbolication/block.h"
#include "utils/enumerator.h"
#include <algorithm>
#include <set>
#include <symbolication/dwarf/die.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>

namespace sym::dw {
using FileIndex = u32;

class SourceCodeFileLNPResolver
{
public:
  SourceCodeFileLNPResolver(LNPHeader *header, std::set<LineTableEntry> &table,
                            std::vector<AddressRange> &sequences,
                            const std::span<const u32> &filesToRecord) noexcept
      : header{header}, mCurrentObjectFileAddressRange(header->mObjectFile->GetAddressRange()), mTable(table),
        mSequences(sequences), mIsStatement(header->default_is_stmt), mFilesToRecord(filesToRecord)
  {
  }

  constexpr bool
  sequence_ended() const noexcept
  {
    return mSequenceEnded;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  StampEntry() noexcept
  {
    // usually lines with value = 0, probably can be given the same value as the previous entry into the table
    // but why even bother? It can't be recorded with 0, because it produces weird behaviors.
    if (ShouldRecord() && mLine != 0) {
      mTable.insert(LineTableEntry{.pc = mAddress,
                                   .line = mLine,
                                   .column = mColumn,
                                   .file = static_cast<u16>(mFile),
                                   .is_stmt = mIsStatement,
                                   .prologue_end = mPrologueEnd,
                                   .basic_block = mBasicBlock,
                                   .epilogue_begin = mEpilogueBegin});
    }
    mDiscriminator = 0;
    mBasicBlock = false;
    mPrologueEnd = false;
    mEpilogueBegin = false;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  advance_pc(u64 adjust_value) noexcept
  {
    const auto address_adjust = ((mOpIndex + adjust_value) / header->max_ops) * header->min_len;
    mAddress += address_adjust;
    mOpIndex = ((mOpIndex + adjust_value) % header->max_ops);
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  advance_line(i64 value) noexcept
  {
    mLine += value;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_file(u64 value) noexcept
  {
    mFile = value;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_column(u64 value) noexcept
  {
    mColumn = value;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  negate_stmt() noexcept
  {
    mIsStatement = !mIsStatement;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  set_basic_block() noexcept
  {
    mBasicBlock = true;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=134
  constexpr void
  const_add_pc() noexcept
  {
    special_opindex_advance(255);
  }

  // DWARF V4 Spec page 120:
  // https://dwarfstd.org/doc/DWARF4.pdf#page=134
  constexpr void
  advance_fixed_pc(u64 advance) noexcept
  {
    mAddress += advance;
    mOpIndex = 0;
  }

  // DWARF V4 Spec page 120:
  // https://dwarfstd.org/doc/DWARF4.pdf#page=134
  constexpr void
  set_prologue_end() noexcept
  {
    mPrologueEnd = true;
  }

  // DWARF V4 Spec page 121:
  // https://dwarfstd.org/doc/DWARF4.pdf#page=135
  constexpr void
  set_epilogue_begin() noexcept
  {
    mEpilogueBegin = true;
  }

  constexpr void
  set_isa(u64 isa) noexcept
  {
    this->mISA = isa;
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=130
  constexpr void
  execute_special_opcode(u8 opcode) noexcept
  {
    special_opindex_advance(opcode);
    const auto line_inc = header->line_base + ((opcode - header->opcode_base) % header->line_range);
    mLine += line_inc;
    StampEntry();
  }

  // https://dwarfstd.org/doc/DWARF4.pdf#page=133
  constexpr void
  SetSequenceEnded() noexcept
  {
    RecordSequence();
    StampEntry();
    // When a sequence ends, state is reset
    mAddress = {0};
    mLine = {1};
    mColumn = {0};
    mOpIndex = {0};
    mFile = {1};
    mIsStatement = header->default_is_stmt;
    mBasicBlock = {false};
    mPrologueEnd = {false};
    mEpilogueBegin = {false};
    mISA = {0};
    mDiscriminator = {0};
  }

  // Records the [begin, end] addressess of the contigous line table entries that we just parsed
  // This is used to be able to search if a SourceCodeFile contains any specific address, and the reason for that
  // is a SourceCodeFile (say foo.h) may contain multiple sequences of line table entries, but where the sequences
  // may be far apart therefore, setting a low_pc, high_pc for that SourceCodeFile is misleading; as it may not
  // actually contain a PC between those two addresses. This is where sequences come in, because then we can do a
  // quick first search on [low,high] and then search the sequence spaces, to actually see if it exists there.
  void
  RecordSequence() noexcept
  {
    mSequenceEnded = true;
    mCurrentSequence.high = mAddress;
    if (ShouldRecord()) {
      mSequences.push_back(mCurrentSequence);
    }
  }

  constexpr void
  SetAddress(u64 addr) noexcept
  {
    if (mSequenceEnded) {
      mSequenceEnded = false;
      mCurrentSequence.low = addr;
    }
    mAddress = addr;
    mOpIndex = 0;
  }

  constexpr void
  define_file(std::string_view filename, u64 dir_index, u64 last_modified, u64 file_size) noexcept
  {
    header->mFileEntries.push_back(FileEntry{filename, dir_index, file_size, {}, last_modified});
  }

  constexpr void
  set_discriminator(u64 value) noexcept
  {
    mDiscriminator = value;
  }

private:
  constexpr void
  special_opindex_advance(u8 opcode)
  {
    const auto advance = op_advance(opcode);
    const auto new_address = mAddress + header->min_len * ((mOpIndex + advance) / header->max_ops);
    const auto new_op_index = (mOpIndex + advance) % header->max_ops;
    mAddress = new_address;
    mOpIndex = new_op_index;
  }

  constexpr u64
  op_advance(u8 opcode) const noexcept
  {
    const auto adjusted_op = opcode - header->opcode_base;
    const auto advance = adjusted_op / header->line_range;
    return advance;
  }

  bool
  ShouldRecord() const noexcept
  {
    return std::ranges::contains(mFilesToRecord, mFile) && AddressInsideVirtualMemoryMappingForObject();
  }

  /// Line Number Program data, unfortunately, very sadly, very... much the f****ry of dwarves, can contain garbled
  /// garbage data In the case of a file template.h, that's included in different files, it may produce LNP data
  /// for two different compilation units but may in the case of one of them, produce address values for the
  /// entries in ranges 0 ... some other low address. This is not the fault of DWARF to be honest though,
  /// apparently it has something to do with the Linker garbage collecting sections that it's removed (because it's
  /// duplicate, for instance). Unfortunately, the DWARF data remains behind, but with garbage data. I wonder if a
  /// bug can be filed here, or if this really is intended behavior? Anyway; we check if the address lands within
  /// the (unrelocated) executable address of this object file, if it's not, we discard it.
  constexpr bool
  AddressInsideVirtualMemoryMappingForObject() const noexcept
  {
    return mCurrentObjectFileAddressRange.Contains(mAddress);
  }

  LNPHeader *header;
  AddressRange mCurrentObjectFileAddressRange;
  std::set<LineTableEntry> &mTable;
  std::vector<AddressRange> &mSequences;
  // State machine register
  u64 mAddress{0};
  u32 mLine{1};
  u32 mColumn{0};
  u16 mOpIndex{0};
  u32 mFile{1};
  bool mIsStatement;
  bool mBasicBlock{false};
  bool mSequenceEnded{false};
  bool mPrologueEnd{false};
  bool mEpilogueBegin{false};
  u8 mISA{0};
  u32 mDiscriminator{0};
  std::span<const u32> mFilesToRecord;
  AddressRange mCurrentSequence;
};

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

  for (const auto &[i, f] : utils::EnumerateView(mFileEntries)) {
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
  const auto *buildDirectory = mObjectFile->GetBuildDirForLineNumberProgram(sec_offset);
  ASSERT(buildDirectory, "Expected build directory to not be null!");
  return (buildDirectory / p).lexically_normal();
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
  auto fileIndex = version == DwarfVersion::D4 ? 1 : 0;

  for (const auto &f : mFileEntries) {
    path_buf.clear();
    const auto index = lnp_index(f.dir_index, version);
    // this should be safe, because the string_views (which we call .data() on) are originally null-terminated
    // and we have not made copies.
    fmt::format_to(std::back_inserter(path_buf), "{}/{}", directories[index].path, f.file_name);
    auto p = std::filesystem::path{path_buf}.lexically_normal();
    if (p.is_relative()) {
      p = CompileDirectoryJoin(p);
    }
    mFileToFileIndex[p].push_back(fileIndex);
    fileIndex++;
  }
}

const LNPHeader::FileEntryContainer &
LNPHeader::FileEntries()
{
  ASSERT(!mFileEntries.empty(), "No file entries has been loaded");
  CacheLNPFilePaths();
  return mFileToFileIndex;
}

std::optional<std::span<const u32>>
LNPHeader::file_entry_index(const std::filesystem::path &p) noexcept
{
  for (const auto &[k, ids] : FileEntries()) {
    if (k == p) {
      return std::span{ids};
    }
  }
  return std::nullopt;
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

std::shared_ptr<std::vector<LNPHeader>>
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

  std::shared_ptr<std::vector<LNPHeader>> headers = std::make_shared<std::vector<LNPHeader>>();
  headers->reserve(header_count);
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
      headers->emplace_back(objectFile, sec_offset, init_len, data_ptr, ptr + init_len, (DwarfVersion)version,
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
      headers->emplace_back(objectFile, sec_offset, init_len, data_ptr, ptr + init_len, (DwarfVersion)version,
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

static bool
LineTableEmpty(std::span<const PerCompilationUnitLineTable> lineTables) noexcept
{
  for (const auto &lt : lineTables) {
    if (!lt.mLineTable.empty()) {
      return false;
    }
  }
  return true;
}

static bool
LineTableContainsPc(std::span<const PerCompilationUnitLineTable> lineTables, AddrPtr unrelocatedPc,
                    u32 *outIndex) noexcept
{
  for (const auto &[idx, lt] : utils::EnumerateView{lineTables}) {
    if (lt.ContainsPc(unrelocatedPc)) {
      if (outIndex) {
        *outIndex = idx;
      }
      return true;
    }
  }
  return false;
}

const LineTableEntry *
SourceCodeFile::GetLineTableEntryFor(AddrPtr relocatedBase, AddrPtr pc) noexcept
{
  if (!IsComputed()) {
    ComputeLineTableForThis();
  }

  if (LineTableEmpty(mLineTables)) {
    return nullptr;
  }

  const AddrPtr searchPc = pc - relocatedBase;

  u32 table = 0;
  const bool rangeContainsPc = LineTableContainsPc(mLineTables, searchPc, &table);

  if (!rangeContainsPc) {
    return nullptr;
  }

  if (!std::ranges::any_of(mLineTableRanges, [searchPc](const auto &range) { return range.Contains(searchPc); })) {
    return nullptr;
  }

  const auto &lineTable = mLineTables[table].mLineTable;

  auto it = std::lower_bound(lineTable.data(), lineTable.data() + lineTable.size(), searchPc,
                             [](const auto &lte, AddrPtr pc) { return lte.pc < pc; });

  if (it != lineTable.data() + lineTable.size()) {
    if (searchPc < it->pc) {
      return it == lineTable.data() ? nullptr : it - 1;
    }
    return it;
  }
  return nullptr;
}

SourceCodeFile::SourceCodeFile(Elf *elf, std::filesystem::path path) noexcept
    : mLineTables(), mSpan(nullptr, nullptr), m(), computed(false), elf(elf), full_path(std::move(path))
{
}

const LineTableEntry *
SourceCodeFile::FindRelocatedLineTableEntry(AddrPtr relocationBase, AddrPtr relocatedAddress) noexcept
{
  if (LineTableEmpty(mLineTables)) {
    return nullptr;
  }

  const auto unrelocatedAddress = relocatedAddress - relocationBase;
  u32 tableIndex = 0;

  if (!LineTableContainsPc(mLineTables, unrelocatedAddress, &tableIndex)) {
    return nullptr;
  }

  const auto &compUnitLineTable = mLineTables[tableIndex].mLineTable;

  auto it =
    std::lower_bound(compUnitLineTable.data(), compUnitLineTable.data() + compUnitLineTable.size(),
                     unrelocatedAddress, [](const LineTableEntry &lte, AddrPtr pc) { return lte.pc < pc; });
  if (it == compUnitLineTable.data() + compUnitLineTable.size()) {
    return nullptr;
  }

  return it;
}

void
SourceCodeFile::AddNewLineNumberProgramHeader(LNPHeader *header) noexcept
{
  ASSERT(!std::ranges::any_of(mLineTables, [header](const auto &t) { return t.mHeader == header; }),
         "Duplicate addition of header");
  mLineTables.push_back({.mHeader = header, .mLineTable = {}});
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

bool
SourceCodeFile::IsComputed() const noexcept
{
  return computed;
}

void
SourceCodeFile::ComputeLineTableForThis() noexcept
{
  std::lock_guard lock(m);
  if (IsComputed()) {
    return;
  }

  std::set<LineTableEntry> unique_ltes{};

  for (auto &table : mLineTables) {
    unique_ltes.clear();
    auto fileIndices = table.mHeader->file_entry_index(full_path);
    ASSERT(fileIndices, "Expected a file entry index but did not find one for {}", full_path->c_str());
    DBGLOG(dwarf, "[lnp]: computing lnp at 0x{:x}", table.mHeader->sec_offset);
    using OpCode = LineNumberProgramOpCode;
    DwarfBinaryReader reader{elf, table.mHeader->data,
                             static_cast<u64>(table.mHeader->data_end - table.mHeader->data)};
    SourceCodeFileLNPResolver state{table.mHeader, unique_ltes, mLineTableRanges, fileIndices.value()};
    while (reader.has_more()) {
      const auto opcode = reader.read_value<OpCode>();
      if (const auto spec_op = std::to_underlying(opcode); spec_op >= table.mHeader->opcode_base) {
        state.execute_special_opcode(spec_op);
        continue;
      }
      if (std::to_underlying(opcode) == 0) {
        // Extended Op Codes
        const auto len = reader.read_uleb128<u64>();
        const auto end = reader.current_ptr() + len;
        auto ext_op = reader.read_value<LineNumberProgramExtendedOpCode>();
        switch (ext_op) {
        case LineNumberProgramExtendedOpCode::DW_LNE_end_sequence:
          state.SetSequenceEnded();
          break;
        case LineNumberProgramExtendedOpCode::DW_LNE_set_address:
          if (table.mHeader->addr_size == 4) {
            const auto addr = reader.read_value<u32>();
            state.SetAddress(addr);
          } else {
            const auto addr = reader.read_value<u64>();
            state.SetAddress(addr);
          }
          break;
        case LineNumberProgramExtendedOpCode::DW_LNE_define_file: {
          if (table.mHeader->version == DwarfVersion::D4) {
            // https://dwarfstd.org/doc/DWARF4.pdf#page=136
            const auto filename = reader.read_string();
            const auto dir_index = reader.read_uleb128<u64>();
            const auto last_modified = reader.read_uleb128<u64>();
            const auto file_size = reader.read_uleb128<u64>();
            state.define_file(filename, dir_index, last_modified, file_size);
          } else {
            PANIC(fmt::format("DWARF V5 line tables not yet implemented"));
          }
          break;
        }
        case LineNumberProgramExtendedOpCode::DW_LNE_set_discriminator: {
          state.set_discriminator(reader.read_uleb128<u64>());
          break;
        }
        default:
          // Vendor extensions
          while (reader.current_ptr() < end) {
            reader.read_value<u8>();
          }
          break;
        }
      }
      switch (opcode) {
      case OpCode::DW_LNS_copy:
        state.StampEntry();
        break;
      case OpCode::DW_LNS_advance_pc:
        state.advance_pc(reader.read_uleb128<u64>());
        break;
      case OpCode::DW_LNS_advance_line:
        state.advance_line(reader.read_leb128<i64>());
        break;
      case OpCode::DW_LNS_set_file:
        state.set_file(reader.read_uleb128<u64>());
        break;
      case OpCode::DW_LNS_set_column:
        state.set_column(reader.read_uleb128<u64>());
        break;
      case OpCode::DW_LNS_negate_stmt:
        state.negate_stmt();
        break;
      case OpCode::DW_LNS_set_basic_block:
        state.set_basic_block();
        break;
      case OpCode::DW_LNS_const_add_pc:
        state.const_add_pc();
        break;
      case OpCode::DW_LNS_fixed_advance_pc:
        state.advance_fixed_pc(reader.read_value<u16>());
        break;
      case OpCode::DW_LNS_set_prologue_end:
        state.set_prologue_end();
        break;
      case OpCode::DW_LNS_set_epilogue_begin:
        state.set_epilogue_begin();
        break;
      case OpCode::DW_LNS_set_isa:
        state.set_isa(reader.read_value<u64>());
        break;
      }
    }

    table.mLineTable.reserve(unique_ltes.size());
    std::ranges::copy(unique_ltes, std::back_inserter(table.mLineTable));
    ASSERT(std::ranges::is_sorted(table.mLineTable, [](auto &a, auto &b) { return a.pc < b.pc; }),
           "Line Table was not sorted by Program Counter!");
    if (table.mLineTable.size() > 2) {
      mSpan.low = std::min(mSpan.low, table.mLineTable.front().pc);
      mSpan.high = std::max(mSpan.high, table.mLineTable.back().pc);
    }
  }
  computed = true;
}

RelocatedSourceCodeFile::RelocatedSourceCodeFile(AddrPtr base_addr,
                                                 const std::shared_ptr<SourceCodeFile> &src_file) noexcept
    : file(*src_file), baseAddr(base_addr)
{
}

RelocatedSourceCodeFile::RelocatedSourceCodeFile(AddrPtr base_addr, SourceCodeFile *src_file) noexcept
    : file(*src_file), baseAddr(base_addr)
{
}

auto
RelocatedSourceCodeFile::FindLineTableEntry(AddrPtr relocatedProgramCounter) const noexcept
  -> const LineTableEntry *
{
  return file.FindRelocatedLineTableEntry(baseAddr, relocatedProgramCounter);
}

AddressRange
RelocatedSourceCodeFile::address_bounds() noexcept
{
  return AddressRange::relocate(file.address_bounds(), baseAddr);
}

} // namespace sym::dw