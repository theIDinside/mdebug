#pragma once
#include "../dwarf_defs.h"
#include "symbolication/block.h"
#include "utils/immutable.h"
#include <common.h>
#include <compare>
#include <elf.h>

class Elf;
class ObjectFile;

namespace sym {
class CompilationUnit;
}

namespace sym::dw {
class UnitData;

struct DirEntry
{
  std::string_view path;
  std::optional<DataBlock> md5;
};

constexpr u64
lnp_index(u64 index, DwarfVersion version) noexcept
{
  switch (version) {
  case DwarfVersion::D2:
    [[fallthrough]];
  case DwarfVersion::D3:
    [[fallthrough]];
  case DwarfVersion::D4:
    return index == 0 ? index : index - 1;
  case DwarfVersion::D5:
    break;
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

struct LNPFilePath
{
  Immutable<Path> mCanonicalPath;
  Immutable<u32> mIndex;
  explicit LNPFilePath(Path &&path, u32 index);
};

/**
 * The processed Line Number Program Header. For the raw byte-to-byte representation see LineHeader4/5
 */
struct LNPHeader
{
  using FileEntryContainer = std::unordered_map<std::string, u32>;
  NO_COPY_DEFAULTED_MOVE(LNPHeader);
  using shr_ptr = std::shared_ptr<LNPHeader>;
  using OpCodeLengths = std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)>;
  using DirEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  using FileNameEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  LNPHeader(ObjectFile *object, u64 section_offset, u64 initial_length, const u8 *data, const u8 *data_end,
            DwarfVersion version, u8 addr_size, u8 min_len, u8 max_ops, bool default_is_stmt, i8 line_base,
            u8 line_range, u8 opcode_base, OpCodeLengths opcode_lengths, std::vector<DirEntry> &&directories,
            std::vector<FileEntry> &&file_names) noexcept;

  std::optional<Path> file(u32 index) const noexcept;
  const FileEntryContainer &FileEntries();

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
  ObjectFile *mObjectFile;
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> std_opcode_lengths;
  std::vector<DirEntry> directories;
  std::vector<FileEntry> mFileEntries;

  static LNPHeader *ReadLineNumberProgramHeader(ObjectFile *objectFile, u64 debugLineOffset) noexcept;

  void SetCompilationUnitBuildDirectory(NonNullPtr<const char> string) noexcept;

private:
  void CacheLNPFilePaths() noexcept;
  Path CompileDirectoryJoin(const Path &p) const noexcept;
  Path FileEntryToPath(const FileEntry& fileEntry) noexcept;
  std::vector<LNPFilePath> mFilePaths;
  FileEntryContainer mFileToFileIndex;
  const char* mCompilationUnitBuildDirectory{nullptr};
};

struct LineTableEntry
{
  AddrPtr pc;
  u32 line;
  u32 column : 17;
  u16 file : 11;
  bool is_stmt : 1;
  bool prologue_end : 1;
  bool epilogue_begin : 1;
  bool IsEndOfSequence : 1 {false};

  friend auto
  operator<=>(const LineTableEntry &l, const LineTableEntry &r) noexcept
  {
    const auto res = (l.pc.get() + l.IsEndOfSequence) <=> (r.pc.get() + r.IsEndOfSequence);
  }

  AddrPtr RelocateProgramCounter(AddrPtr base) const noexcept;
};

struct LineTableEntryAddress
{
  AddrPtr pc;
};

struct LineTableEntryInfo
{
  u32 line;
  u32 column : 17;
  u16 file : 10;
  bool is_stmt : 1;
  bool prologue_end : 1;
  bool basic_block : 1;
  bool epilogue_begin : 1;
};

class ComponentLineTable
{
  std::vector<LineTableEntryAddress> mEntryAddress;
  std::vector<LineTableEntryInfo> mEntryInfo;

public:
  LineTableEntryInfo *
  Info(LineTableEntryAddress *entry) noexcept
  {
    size_t index = entry - mEntryAddress.data();
    return &mEntryInfo[index];
  }

  void
  Reserve(u32 size) noexcept
  {
    mEntryAddress.reserve(size);
    mEntryInfo.reserve(size);
  }

  void
  Push(const LineTableEntry &lte)
  {
    mEntryAddress.push_back({lte.pc});
    mEntryInfo.push_back({});
  }
};

struct RelocatedLteIterator
{
  // using Iter = std::vector<LineTableEntry>::const_iterator;
  using Iter = const LineTableEntry *;

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

// A source code file is a file that's either represented (and thus realized, when parsed) in the Line Number
// Program or referenced somehow from an actual Compilation Unit/Translation unit; Meaning, DWARF does not
// represent it as a single, solitary "binary blob" of debug symbol info. Something which generally tend to only be
// "source code file" (Our own, Midas definition for it) are header files which can be included in many different
// s files. This is generally true for templated code, for instance. A `SourceCodeFile` does not "own" any
// particular
// debug info metadata that responsibility is left to a `SourceFileSymbolInfo`. I guess, GDB also makes a sort of
// similar distinction with it's "symtabs" and "psymtabs" - I guess?

struct PerCompilationUnitLineTable
{
  LNPHeader *mHeader;
  // Resolved lazily when needed, by walking `line_table`
  std::vector<LineTableEntry> mLineTable;

  constexpr bool
  ContainsPc(AddrPtr unrelocatedPc) const noexcept
  {
    return !mLineTable.empty() && (mLineTable.front().pc <= unrelocatedPc && unrelocatedPc < mLineTable.back().pc);
  }
};

template <typename Container, typename T>
concept AppendableContainer = requires(Container c) { c.Append(T{}); } || requires(Container c) {
  c.PushBack(T{});
} || requires(Container c) { c.push_back(T{}); };

struct LineTableRange
{
  u32 mStartIndex;
  u32 mEndExclusiveIndex;

  constexpr u32
  Count() const noexcept
  {
    return mEndExclusiveIndex - mStartIndex;
  }
};

class SourceCodeFile
{
public:
  NO_COPY(SourceCodeFile);
  using Ref = std::shared_ptr<SourceCodeFile>;

private:
  sym::CompilationUnit *mCompilationUnit;
  // Resolved lazily when needed, by walking `line_table`
  // Contains <offset, count> pairs into the complete linetable, which are the ranges that are mapped (have the
  // file index = this one) to this source code file
  std::vector<LineTableRange> mLineTableRanges;
  AddressRange mSpan{nullptr, nullptr};
  const Elf *elf;
  u32 mLineInfoFileIndex;
  bool IsComputed() const noexcept;
  void ComputeLineTableForThis() noexcept;
  SourceCodeFile(CompilationUnit *compilationUnit, const Elf *elf, std::filesystem::path &&path,
                 u32 fileIndex) noexcept;

public:
  Immutable<std::filesystem::path> full_path;
  static SourceCodeFile::Ref Create(sym::CompilationUnit *compilationUnit, const Elf *elf, std::filesystem::path path,
                                    u32 lnpFileIndex) noexcept;
  sym::CompilationUnit *GetOwningCompilationUnit() const noexcept;
  auto address_bounds() noexcept -> AddressRange;
  bool HasAddressRange() noexcept;
  void ReadInSourceCodeLineTable(std::vector<LineTableEntry> &result) noexcept;
  void SetLineTableRanges(const std::vector<std::pair<u32, u32>> &ranges) noexcept;
  u32
  GetFileIndex() const noexcept
  {
    return mLineInfoFileIndex;
  }

  constexpr AddrPtr
  StartAddress() const noexcept
  {
    return mSpan.StartPc();
  }
  constexpr AddrPtr
  EndAddress() const noexcept
  {
    return mSpan.EndPc();
  }
};

std::vector<LNPHeader> read_lnp_headers(ObjectFile *objectFile) noexcept;
} // namespace sym::dw
