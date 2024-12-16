#pragma once
#include "../dwarf_defs.h"
#include "symbolication/block.h"
#include "utils/immutable.h"
#include <common.h>

class Elf;
struct ObjectFile;

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
  using FileEntryContainer = std::unordered_map<std::string, std::vector<u32>>;
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
  std::optional<std::span<const u32>> file_entry_index(const std::filesystem::path &p) noexcept;
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

private:
  void CacheLNPFilePaths() noexcept;
  Path CompileDirectoryJoin(const Path &p) const noexcept;
  std::vector<LNPFilePath> mFilePaths;
  std::unordered_map<std::string, std::vector<u32>> mFileToFileIndex;
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

  AddrPtr RelocateProgramCounter(AddrPtr base) const noexcept;
};

struct LineTableEntryAddress {
  AddrPtr pc;
};

struct LineTableEntryInfo {
  u32 line;
  u32 column : 17;
  u16 file : 10;
  bool is_stmt : 1;
  bool prologue_end : 1;
  bool basic_block : 1;
  bool epilogue_begin : 1;
};

class ComponentLineTable {
  std::vector<LineTableEntryAddress> mEntryAddress;
  std::vector<LineTableEntryInfo> mEntryInfo;
public:
  LineTableEntryInfo* Info(LineTableEntryAddress* entry) noexcept {
    size_t index = entry - mEntryAddress.data();
    return &mEntryInfo[index];
  }

  void Reserve(u32 size) noexcept {
    mEntryAddress.reserve(size);
    mEntryInfo.reserve(size);
  }

  void Push(const LineTableEntry& lte) {
    mEntryAddress.push_back({ lte.pc });
    mEntryInfo.push_back({});
  }
};

struct RelocatedLteIterator
{
  // using Iter = std::vector<LineTableEntry>::const_iterator;
  using Iter = LineTableEntry*;

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
  mutable std::vector<LineTableEntry> mLineTable;
  mutable std::vector<AddressRange> mLineTableRanges;
  mutable AddrPtr low;
  mutable AddrPtr high;
  mutable std::mutex m;
  mutable bool computed;
  Elf *elf;
  bool is_computed() const noexcept;
  void ComputeLineTableForThis() const noexcept;

public:
  SourceCodeFile(Elf *elf, std::filesystem::path path, std::vector<LNPHeader *> &&headers) noexcept;
  Immutable<std::filesystem::path> full_path;

  std::span<const LineTableEntry> GetLineTable() const noexcept;
  const LineTableEntry* GetProgramCounterUsingBase(AddrPtr relocatedBase, AddrPtr pc) noexcept;
  auto begin(AddrPtr relocatedBase) const noexcept -> RelocatedLteIterator;
  auto end(AddrPtr relocatedBase) const noexcept -> RelocatedLteIterator;

  auto first_linetable_entry(AddrPtr relocatedBase, u32 line,
                             std::optional<u32> column) -> std::optional<LineTableEntry>;

  auto find_by_pc(AddrPtr base, AddrPtr pc) const noexcept -> std::optional<RelocatedLteIterator>;
  auto add_header(LNPHeader *header) noexcept -> void;
  auto address_bounds() noexcept -> AddressRange;
  bool HasAddressRange() noexcept;
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
} // namespace sym::dw
