/** LICENSE TEMPLATE */
#include "cu_symbol_info.h"
#include "dwarf/debug_info_reader.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "dwarf_attribute_value.h"
#include "fnsymbol.h"
#include "objfile.h"
#include "symbolication/dwarf/die_ref.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_defs.h"
#include "utils/immutable.h"
#include "utils/logger.h"
#include <array>
#include <list>
#include <memory_resource>
#include <set>
#include <utils/filter.h>

namespace mdb::sym {

class SourceCodeFileLNPResolver
{
public:
  SourceCodeFileLNPResolver(CompilationUnit *compilationUnit, dw::LNPHeader *header,
                            std::vector<dw::LineTableEntry> &table, std::vector<AddressRange> &sequences) noexcept
      : mLineNumberProgramHeader{header}, mCurrentObjectFileAddressRange(header->mObjectFile->GetAddressRange()),
        mTable(table), mSequences(sequences), mIsStatement(header->mDefaultIsStatement)
  {
  }

  std::vector<std::vector<std::pair<u32, u32>>>
  CreateSubFileMappings() const noexcept
  {
    std::vector<std::vector<std::pair<u32, u32>>> result;
    result.reserve(mLineNumberProgramHeader->mFileEntries.size() + 1);
    result.resize(mLineNumberProgramHeader->mFileEntries.size() + 1);

    auto current_file = mTable.front().file;
    auto currentIndex = 0;

    result[current_file].push_back({0, 0});

    for (const auto &lte : mTable) {
      if (lte.file != current_file) {
        result[current_file].back().second = currentIndex;
        if (result[current_file].back().first == result[current_file].back().second) {
          result[current_file].pop_back();
        }
        current_file = lte.file;
        result[current_file].emplace_back(currentIndex, currentIndex);
      }
      ++currentIndex;
    }
    // finish the last entry being processed.
    result[current_file].back().second = currentIndex;

    return result;
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
    if (ShouldRecord() && (mLine != 0 || mSequenceEnded)) {
      mTable.push_back(dw::LineTableEntry{.pc = mAddress,
                                          .line = mLine,
                                          .column = mColumn,
                                          .file = static_cast<u16>(mFile),
                                          .is_stmt = mIsStatement,
                                          .prologue_end = mPrologueEnd,
                                          .epilogue_begin = mEpilogueBegin,
                                          .IsEndOfSequence = (mSequenceEnded || (mLine == 0))});
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
    const auto address_adjust =
      ((mOpIndex + adjust_value) / mLineNumberProgramHeader->mMaxOps) * mLineNumberProgramHeader->mMinLength;
    mAddress += address_adjust;
    mOpIndex = ((mOpIndex + adjust_value) % mLineNumberProgramHeader->mMaxOps);
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
    const auto line_inc = mLineNumberProgramHeader->mLineBase + ((opcode - mLineNumberProgramHeader->mOpcodeBase) %
                                                                 mLineNumberProgramHeader->mLineRange);
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
    mIsStatement = mLineNumberProgramHeader->mDefaultIsStatement;
    mBasicBlock = {false};
    mPrologueEnd = {false};
    mEpilogueBegin = {false};
    mSequenceEnded = {false};
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
    mLineNumberProgramHeader->mFileEntries.push_back(
      dw::FileEntry{filename, dir_index, file_size, {}, last_modified});
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
    const auto new_address =
      mAddress + mLineNumberProgramHeader->mMinLength * ((mOpIndex + advance) / mLineNumberProgramHeader->mMaxOps);
    const auto new_op_index = (mOpIndex + advance) % mLineNumberProgramHeader->mMaxOps;
    mAddress = new_address;
    mOpIndex = new_op_index;
  }

  constexpr u64
  op_advance(u8 opcode) const noexcept
  {
    const auto adjusted_op = opcode - mLineNumberProgramHeader->mOpcodeBase;
    const auto advance = adjusted_op / mLineNumberProgramHeader->mLineRange;
    return advance;
  }

  bool
  ShouldRecord() const noexcept
  {
    return AddressInsideVirtualMemoryMappingForObject();
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

  dw::LNPHeader *mLineNumberProgramHeader;
  AddressRange mCurrentObjectFileAddressRange;
  std::vector<dw::LineTableEntry> &mTable;
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
  AddressRange mCurrentSequence;
};

PartialCompilationUnitSymbolInfo::PartialCompilationUnitSymbolInfo(dw::UnitData *data) noexcept
    : unit_data(data), fns(), imported_units()
{
}

PartialCompilationUnitSymbolInfo::PartialCompilationUnitSymbolInfo(PartialCompilationUnitSymbolInfo &&o) noexcept
    : unit_data(o.unit_data), fns(std::move(o.fns)), imported_units(std::move(o.imported_units))
{
}

PartialCompilationUnitSymbolInfo &
PartialCompilationUnitSymbolInfo::operator=(PartialCompilationUnitSymbolInfo &&rhs) noexcept
{
  if (this == &rhs) {
    return *this;
  }
  unit_data = rhs.unit_data;
  fns = std::move(rhs.fns);
  imported_units = std::move(rhs.imported_units);
  return *this;
}

CompilationUnit::CompilationUnit(dw::UnitData *unitData) noexcept
    : mUnitData(unitData), mCompilationUnitName("unknown_cu_name")
{
}

void
CompilationUnit::SetAddressBoundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept
{
  DBGLOG(dwarf, "cu={} low_pc={} .. {} ({})", mUnitData->SectionOffset(), lowest, end_exclusive,
         mUnitData->GetObjectFile()->GetFilePath().filename().c_str());
  mPcStart = lowest;
  mPcEndExclusive = end_exclusive;
}

bool
CompilationUnit::LineTableComputed() noexcept
{
  return computed;
}

std::span<const dw::LineTableEntry>
CompilationUnit::GetLineTable() const noexcept
{
  return mLineTable;
}

std::span<const AddressRange>
CompilationUnit::AddressRanges() const noexcept
{
  return mAddressRanges;
}

void
CompilationUnit::ComputeLineTable() noexcept
{
  std::lock_guard lock(m);
  PROFILE_SCOPE_ARGS("ComputeLineTable", "symbolication", PEARG("compunit", mLineNumberProgram->mSectionOffset));
  if (LineTableComputed()) {
    return;
  }

  std::vector<dw::LineTableEntry> unique_ltes{};

  DBGLOG(dwarf, "[lnp]: computing lnp at {}", mLineNumberProgram->mSectionOffset);
  using OpCode = LineNumberProgramOpCode;
  std::vector<AddressRange> sequences;
  DwarfBinaryReader reader{mUnitData->GetObjectFile()->GetElf(), mLineNumberProgram->mData,
                           static_cast<u64>(mLineNumberProgram->mDataEnd - mLineNumberProgram->mData)};

  SourceCodeFileLNPResolver state{this, mLineNumberProgram, unique_ltes, sequences};
  while (reader.has_more()) {
    const auto opcode = reader.read_value<OpCode>();
    if (const auto spec_op = std::to_underlying(opcode); spec_op >= mLineNumberProgram->mOpcodeBase) {
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
        if (mLineNumberProgram->mAddrSize == 4) {
          const auto addr = reader.read_value<u32>();
          state.SetAddress(addr);
        } else {
          const auto addr = reader.read_value<u64>();
          state.SetAddress(addr);
        }
        break;
      case LineNumberProgramExtendedOpCode::DW_LNE_define_file: {
        if (mLineNumberProgram->mVersion == DwarfVersion::D4) {
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

  mLineTable.reserve(unique_ltes.size());

  std::sort(std::begin(unique_ltes), std::end(unique_ltes), [](auto &a, auto &b) { return a.pc < b.pc; });

  std::ranges::copy(unique_ltes, std::back_inserter(mLineTable));
  ASSERT(std::ranges::is_sorted(mLineTable, [](auto &a, auto &b) { return a.pc < b.pc; }),
         "Line Table was not sorted by Program Counter!");
  if (mLineTable.size() > 2) {
    mPcStart = std::min(mPcStart, mLineTable.front().pc);
    mPcEndExclusive = std::max(mPcEndExclusive, mLineTable.back().pc);
  }
  computed = true;

  const auto sourceCodeTableMapping = state.CreateSubFileMappings();
  // Our "hash"-function.
  const auto hashIndex = [v = mLineNumberProgram->mVersion](u32 index) -> u32 {
    // u8 4-5 will overflow and we reduce it to 1.
    return index + std::min<u32>(u32{std::to_underlying(v)} - u32{std::to_underlying(DwarfVersion::D5)}, 1);
  };

  for (auto i = 0u; i < sourceCodeTableMapping.size() - 1; ++i) {
    // Versions below DWARF5 have their index starting at 1. So we "hash" the index with our stupid simple hashing
    // function
    auto adjusted = hashIndex(i);
    mSourceCodeFileMappings[adjusted]->AddLineTableRanges(sourceCodeTableMapping[adjusted]);
  }
}

// the line table consists of a list of directory entries and file entries
// that are relevant for this line table. As such, we are informed of all the
// source files used over some range of addressess etc. These source files
// might be included in multiple places (compilation units). We de-duplicate them
// by storing them by name in `ObjectFile` in a map and then add the references to them
// to the newly minted compilation unit handle (process_source_code_files)
void
CompilationUnit::ProcessSourceCodeFiles(dw::LNPHeader *header) noexcept
{
  auto objectFile = mUnitData->GetObjectFile();
  mLineNumberProgram = header;
  header->SetCompilationUnitBuildDirectory(NonNull(*mUnitData->GetBuildDirectory()));

  DBGLOG(dwarf, "read files from lnp=0x{}, comp unit={} '{}'", mLineNumberProgram->mSectionOffset,
         mUnitData->SectionOffset(), mCompilationUnitName);

  for (const auto &[fullPath, v] : mLineNumberProgram->FileEntries()) {
    auto ptr = dw::SourceCodeFile::Create(this, objectFile->GetElf(), fullPath, v);
    for (auto index : v.FileIndices()) {
      ASSERT(!mSourceCodeFileMappings.contains(index), "index {} already added!", index);
      mSourceCodeFileMappings[index] = ptr;
    }
  }
}

std::unordered_map<u32, std::shared_ptr<dw::SourceCodeFile>> &
CompilationUnit::sources() noexcept
{
  return mSourceCodeFileMappings;
}

void
CompilationUnit::SetUnitName(std::string_view name) noexcept
{
  mCompilationUnitName = name;
}

void
CompilationUnit::SetAddressRanges(std::vector<AddressRange> &&ranges) noexcept
{
  mAddressRanges = std::move(ranges);
}

bool
CompilationUnit::HasKnownAddressBoundary() const noexcept
{
  return mPcStart != nullptr && mPcEndExclusive != nullptr;
}

std::pair<dw::SourceCodeFile *, const dw::LineTableEntry *>
CompilationUnit::GetLineTableEntry(AddrPtr unrelocatedAddress) noexcept
{
  if (!LineTableComputed()) {
    ComputeLineTable();
  }

  if (unrelocatedAddress < mLineTable.front().pc || mLineTable.back().pc < unrelocatedAddress) {
    return {nullptr, nullptr};
  }

  auto it = std::lower_bound(std::cbegin(mLineTable), std::cend(mLineTable), unrelocatedAddress,
                             [](const dw::LineTableEntry &lte, AddrPtr pc) { return lte.pc < pc; });

  if (it == std::cend(mLineTable)) {
    return std::pair<dw::SourceCodeFile *, const dw::LineTableEntry *>{nullptr, nullptr};
  }

  if (it->pc == unrelocatedAddress) {
    return std::pair{GetFileByLineProgramIndex(it->file), it.base()};
  } else {
    --it;
    // clang-format off
    // Means we're at an instruction where we have no source information. On linux, we seemingly produce interrupt instructions, as padding
    // Look at this output from one of the test subjects: stackframes at the function static void bar(int a, int b):
    // 201d93:       c3                      ret      return instruction in the function
    // 201d94:       cc                      int3     in the LNP, this is the last entry, with end_sequence = true
    // 201d95:       cc                      int3     these are not represented in the Line Number Program data
    // 201d96:       cc                      int3     but go on until a 16-byte boundary.
    // clang-format on

    // We found no address that is spanned by 2 consecutive LTE's
    if (it->IsEndOfSequence) {
      return {GetFileByLineProgramIndex(it->file), nullptr};
    }
    ASSERT(it->pc <= unrelocatedAddress && (it + 1)->pc > unrelocatedAddress && !it->IsEndOfSequence,
           "Line table is not ordered by PC - table in bad state (end of sequence={})", it->IsEndOfSequence);

    return std::pair{GetFileByLineProgramIndex(it->file), it.base()};
  }
}

dw::SourceCodeFile *
CompilationUnit::GetFileByLineProgramIndex(u32 index) noexcept
{
  // TODO(simon): do some form of O(1) lookup instead. But there's trickiness here. I don't want it to be
  // complicated but

  if (auto ptr = mSourceCodeFileMappings[index]; ptr) {
    return ptr.get();
  }

  return nullptr;
}

AddrPtr
CompilationUnit::StartPc() const noexcept
{
  return mPcStart;
}

AddrPtr
CompilationUnit::EndPc() const noexcept
{
  return mPcEndExclusive;
}

std::string_view
CompilationUnit::name() const noexcept
{
  return mCompilationUnitName;
}

bool
CompilationUnit::IsFunctionSymbolsResolved() const noexcept
{
  return !mFunctionSymbols.empty();
}

sym::FunctionSymbol *
CompilationUnit::GetFunctionSymbolByProgramCounter(AddrPtr pc) noexcept
{
  PROFILE_SCOPE("CompilationUnit::GetFunctionSymbolByProgramCounter", "symbolication");
  if (!IsFunctionSymbolsResolved()) {
    PROFILE_SCOPE_END_ARGS("CompilationUnit::PrepareFunctionSymbols", "symbolication",
                           PEARG("symbols", mFunctionSymbols.size()),
                           PEARG("comp_unit", mUnitData->SectionOffset()),
                           PEARG("symbolfile", mUnitData->GetObjectFile()->GetFilePath().filename().c_str()));
    PrepareFunctionSymbols();
  }

  auto iter = std::find_if(mFunctionSymbols.begin(), mFunctionSymbols.end(),
                           [pc](sym::FunctionSymbol &fn) { return fn.StartPc() <= pc && pc < fn.EndPc(); });
  if (iter != std::end(mFunctionSymbols)) {
    return iter.base();
  }
  return nullptr;
}

dw::UnitData *
CompilationUnit::get_dwarf_unit() const noexcept
{
  return mUnitData;
}

std::optional<Path>
CompilationUnit::get_lnp_file(u32 index) noexcept
{
  // TODO(simon): we really should store a pointer to the line number program table (or header) in either UnitData
  // or SourceFileSymbolInfo directly.
  return mLineNumberProgram->file(index);
}

using DieOffset = u64;
using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;

struct ResolveFnSymbolState
{
  CompilationUnit *symtab;
  std::string_view name{};
  std::string_view mangled_name{};
  // a namespace or a class, so foo::foo, like a constructor, or mdb::foo for a namespace with foo as a fn, for
  // instance.
  std::string_view namespace_ish{};
  AddrPtr low_pc{nullptr};
  AddrPtr high_pc{nullptr};
  u8 maybe_count{0};
  std::optional<std::span<const u8>> frame_base_description{};
  sym::Type *ret_type{nullptr};

  std::optional<u32> line{std::nullopt};
  std::optional<std::string> lnp_file{std::nullopt};

  explicit ResolveFnSymbolState(CompilationUnit *symtable) noexcept : symtab(symtable) {}

  std::array<dw::IndexedDieReference, 3> maybe_origin_dies{};
  bool
  done(bool has_no_references) const
  {
    if (!name.empty()) {
      return low_pc != nullptr && high_pc != nullptr;
    } else if (!mangled_name.empty()) {
      // if we have die references, we are not done
      return has_no_references && low_pc != nullptr && high_pc != nullptr;
    } else {
      return false;
    }
  }

  sym::FunctionSymbol
  complete()
  {
    std::optional<SourceCoordinate> source =
      lnp_file.transform([&](auto &&path) { return SourceCoordinate{std::move(path), line.value_or(0), 0}; });
    if (lnp_file) {
      ASSERT(lnp_file.value().empty(), "Should have moved std string!");
    }

    return sym::FunctionSymbol{low_pc,
                               high_pc,
                               name.empty() ? mangled_name : name,
                               namespace_ish,
                               ret_type,
                               maybe_origin_dies,
                               *symtab,
                               frame_base_description.value_or(std::span<const u8>{}),
                               std::move(source)};
  }

  void
  add_maybe_origin(dw::IndexedDieReference indexed) noexcept
  {
    if (maybe_count < 3 && !std::any_of(maybe_origin_dies.begin(), maybe_origin_dies.begin() + maybe_count,
                                        [&](const auto &idr) { return idr == indexed; })) {
      maybe_origin_dies[maybe_count++] = indexed;
    }
  }
};

static std::optional<dw::DieReference>
follow_reference(CompilationUnit &src_file, ResolveFnSymbolState &state, dw::DieReference ref) noexcept
{
  std::optional<dw::DieReference> additional_die_reference = std::optional<dw::DieReference>{};
  dw::UnitReader reader = ref.GetReader();
  const auto &abbreviation = ref.GetUnitData()->GetAbbreviation(ref.GetDie()->mAbbreviationCode);
  if (!abbreviation.mIsDeclaration) {
    state.add_maybe_origin(ref.AsIndexed());
  }

  if (const auto parent = ref.GetDie()->GetParent();
      maybe_null_any_of<DwarfTag::DW_TAG_class_type, DwarfTag::DW_TAG_structure_type>(parent)) {
    dw::DieReference parentReference{ref.GetUnitData(), parent};
    if (auto class_name = parentReference.ReadAttribute(Attribute::DW_AT_name); class_name) {
      state.namespace_ish = class_name->AsStringView();
    }
  }

  for (const auto &attr : abbreviation.mAttributes) {
    auto value = ReadAttributeValue(reader, attr, abbreviation.mImplicitConsts);
    switch (value.name) {
    case Attribute::DW_AT_name:
      state.name = value.AsStringView();
      break;
    case Attribute::DW_AT_linkage_name:
      state.mangled_name = value.AsStringView();
      break;
    // is address-representable?
    case Attribute::DW_AT_low_pc:
      state.low_pc = value.AsAddress();
      break;
    case Attribute::DW_AT_decl_file: {
      if (!state.lnp_file) {
        state.lnp_file =
          src_file.get_lnp_file(value.AsUnsignedValue()).transform([](auto &&p) { return p.string(); });
        CDLOG(ref.GetUnitData() != src_file.get_dwarf_unit(), core,
              "[dwarf]: Cross CU requires (?) another LNP. ref.cu = {}, src file cu={}",
              ref.GetUnitData()->SectionOffset(), src_file.get_dwarf_unit()->SectionOffset());
      }
    } break;
    case Attribute::DW_AT_decl_line:
      if (!state.line) {
        state.line = value.AsUnsignedValue();
      }
      break;
    case Attribute::DW_AT_high_pc:
      if (value.form != AttributeForm::DW_FORM_addr) {
        state.high_pc = state.low_pc.get() + value.AsAddress();
      } else {
        state.high_pc = value.AsAddress();
      }
      break;
    case Attribute::DW_AT_specification:
    case Attribute::DW_AT_abstract_origin: {
      const auto declaring_die_offset = value.AsUnsignedValue();
      additional_die_reference =
        ref.GetUnitData()->GetObjectFile()->GetDebugInfoEntryReference(declaring_die_offset);
    } break;
    default:
      break;
    }
  }
  return additional_die_reference;
}

void
CompilationUnit::PrepareFunctionSymbols() noexcept
{
  const auto &dies = mUnitData->GetDies();

  dw::UnitReader reader{mUnitData};
  // For a function symbol, we want to record a DIE, from which we can reach all it's (possible) references.
  // Unfortunately DWARF doesn't seem to define a "OWNING" die. Which is... unfortunate. So we have to guess. But
  // 2-3 should be enough.
  std::array<u8, 512> buf;
  std::pmr::monotonic_buffer_resource rsrc{&buf, std::size(buf), std::pmr::null_memory_resource()};
  std::pmr::polymorphic_allocator<u8> allocator{&rsrc};
  for (const auto &die : dies) {
    switch (die.mTag) {
    case DwarfTag::DW_TAG_subprogram:
      break;
    // TODO: implement support for inlined subroutines. They introduce some substantial complexity, so for now
    // we don't care much for it. The reason is this: multiple inlined subroutine dies may refer to the same
    // "function symbol" that we will want to create for it, problem is, we have no way of doing so at the moment.
    case DwarfTag::DW_TAG_inlined_subroutine:
      [[fallthrough]];
    default:
      continue;
    }
    const auto &abbreviation = mUnitData->GetAbbreviation(die.mAbbreviationCode);
    // Skip declarations - we will visit them if necessary, but on their own they can't tell us anything.
    if (abbreviation.mIsDeclaration || !abbreviation.mIsAddressable) {
      continue;
    }

    rsrc.release();
    reader.SeekDie(die);
    ResolveFnSymbolState state{this};

    std::pmr::list<dw::DieReference> &die_refs = *allocator.new_object<std::pmr::list<dw::DieReference>>();
    for (const auto &attr : abbreviation.mAttributes) {
      auto value = ReadAttributeValue(reader, attr, abbreviation.mImplicitConsts);
      switch (value.name) {
      case Attribute::DW_AT_frame_base:
        state.frame_base_description = as_span(value.AsDataBlock());
        break;
      case Attribute::DW_AT_name:
        state.name = value.AsStringView();
        break;
      case Attribute::DW_AT_linkage_name:
        state.mangled_name = value.AsStringView();
        break;
      case Attribute::DW_AT_low_pc:
        state.low_pc = value.AsAddress();
        break;
      case Attribute::DW_AT_high_pc:
        if (value.form != AttributeForm::DW_FORM_addr) {
          state.high_pc = state.low_pc.get() + value.AsAddress();
        } else {
          state.high_pc = value.AsAddress();
        }
        break;
      case Attribute::DW_AT_decl_file: {
        ASSERT(!state.lnp_file.has_value(), "lnp file has been set already, to {}, new {}", state.lnp_file.value(),
               value.AsUnsignedValue());
        state.lnp_file = get_lnp_file(value.AsUnsignedValue()).transform([](auto &&p) { return p.string(); });
      } break;
      case Attribute::DW_AT_decl_line:
        ASSERT(!state.line.has_value(), "file line number has been set already, to {}, new {}", state.line.value(),
               value.AsUnsignedValue());
        state.line = value.AsUnsignedValue();
        break;
      case Attribute::DW_AT_specification:
      case Attribute::DW_AT_abstract_origin: {
        const auto declaring_die_offset = value.AsUnsignedValue();
        if (auto die_ref = mUnitData->GetObjectFile()->GetDebugInfoEntryReference(declaring_die_offset); die_ref) {
          die_refs.push_back(*die_ref);
        } else {
          DBGLOG(core, "Could not find die reference");
        }
        break;
      }
      case Attribute::DW_AT_type: {
        const auto type_id = value.AsUnsignedValue();
        auto obj = mUnitData->GetObjectFile();
        const auto ref = obj->GetDebugInfoEntryReference(type_id);
        state.ret_type = obj->GetTypeStorage()->GetOrCreateNewType(ref->AsIndexed());
        break;
      }
      default:
        break;
      }
    }

    state.add_maybe_origin(dw::IndexedDieReference{mUnitData, mUnitData->index_of(&die)});
    if (state.done(die_refs.empty())) {
      mFunctionSymbols.emplace_back(state.complete());
    } else {
      // reset e = end() at each iteration, because we might have extended the list during iteration.
      for (auto it = die_refs.begin(), e = die_refs.end(); it != e; ++it) {
        auto new_ref = follow_reference(*this, state, *it);
        // we use a linked list here, *specifically* so we can push back references while iterating.
        if (new_ref) {
          die_refs.push_back(*new_ref);
          e = die_refs.end();
        }

        if (state.done(std::distance(++auto{it}, e) == 0)) {
          mFunctionSymbols.emplace_back(state.complete());
          break;
        }
      }
    }
  }
  std::sort(mFunctionSymbols.begin(), mFunctionSymbols.end(), FunctionSymbol::Sorter());
}

AddressToCompilationUnitMap::AddressToCompilationUnitMap() noexcept : mutex(), mapping() {}

std::vector<CompilationUnit *>
AddressToCompilationUnitMap::find_by_pc(AddrPtr pc) noexcept
{
  if (auto res = mapping.Find(pc); res) {
    auto result = std::move(res.value());
    return result;
  } else {
    return {};
  }
}

void
AddressToCompilationUnitMap::add_cus(std::span<CompilationUnit *> compUnits) noexcept
{
  std::lock_guard lock(mutex);
  for (CompilationUnit *compilationUnit : compUnits) {
    for (const auto subRange : compilationUnit->AddressRanges()) {
      add_cu(subRange.StartPc(), subRange.EndPc(), compilationUnit);
    }
    add_cu(compilationUnit->StartPc(), compilationUnit->EndPc(), compilationUnit);
  }
}

void
AddressToCompilationUnitMap::add_cu(AddrPtr start, AddrPtr end, CompilationUnit *cu) noexcept
{
  mapping.AddMapping(start, end, cu);
}

} // namespace mdb::sym