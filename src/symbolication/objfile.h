/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp.h>
#include <interface/dap/types.h>
#include <symbolication/block.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/die_ref.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/elf.h>
#include <symbolication/elf_symbols.h>
#include <symbolication/value_visualizer.h>
#include <tracer.h>

// std
#include <string_view>
#include <type_traits>

// system
#include <sys/mman.h>

namespace mdb {

namespace tc {
class SupervisorState;
}

struct WriteError
{
  AddrPtr mAddress;
  u32 mBytesWritten;
  int mSysErrorNumber;
};

struct ObjectFileDescriptor
{
  std::filesystem::path mPath;
  AddrPtr mAddress;
};

struct AuxvElement
{
  u64 mId;
  u64 mEntry;
};

struct Auxv
{
  std::vector<AuxvElement> mContents;
};

struct VariableContext;

class NonExecutableCompilationUnitFile;

template <typename T> using Optional = std::optional<T>;

namespace alloc {
class ArenaResource;
};

namespace sym {
class Unwinder;
class Type;
class Value;
class DebugAdapterSerializer;
class ValueResolver;
class IValueResolve;
enum class VariableSet : u8;
enum class FrameVariableKind : u8;

namespace dw {
struct LNPHeader;
class UnitData;
class LineTable;
class DieReference;
struct ObjectFileNameIndex;
} // namespace dw
} // namespace sym

class Elf;
class SymbolFile;
struct ElfSection;

struct BreakpointLookup
{
  AddrPtr address;
  std::optional<LocationSourceInfo> loc_src_info;
};

/**
 * The owning data-structure that all debug info symbols point to. The ObjFile is meant
 * to outlive them all, so it's safe to take raw pointers into `loaded_binary`.
 */
class ObjectFile
{
  friend SymbolFile;
  Path mObjectFilePath;
  std::string mObjectFileId;
  u64 mSize;
  const u8 *mLoadedBinary;
  Elf *elf{ nullptr };
  alloc::ArenaResource *mPrivateAllocator{ nullptr };
  std::unique_ptr<sym::Unwinder> unwinder{ nullptr };

  // Address bounds determined by reading the program segments of the elf binary
  AddressRange mUnrelocatedAddressBounds{};
  std::unique_ptr<TypeStorage> mTypeStorage;

  std::unordered_map<std::string_view, Index> mMinimalFunctionSymbols;
  std::vector<MinSymbol> mMinimalFunctionSymbolsSorted;
  std::unordered_map<std::string_view, MinSymbol> mMinimalObjectSymbols;

  std::unordered_map<std::string_view, Index> mMinimalDynamicFunctionSymbols;
  std::vector<MinSymbol> mMinimalDynamicFunctionSymbolsSorted;
  std::unordered_map<std::string_view, MinSymbol> mMinimalDynamicObjectSymbols;

  std::mutex mLnpHeaderMutex{};
  std::unordered_map<u64, sym::dw::LNPHeader *> mLineNumberProgramHeaders{};

  std::mutex mUnitDataWriteLock;
  std::vector<sym::dw::UnitData *> mCompileUnits;
  std::unique_ptr<sym::dw::ObjectFileNameIndex> mNameToDieIndex;

  std::mutex mCompileUnitWriteLock;
  std::vector<sym::CompilationUnit *> mCompilationUnits;
  std::unordered_map<u64, sym::dw::UnitData *> mTypeToUnitDataMap{};

  // TODO(simon): use std::string_view here instead of std::filesystem::path, the std::string_view
  //   can actually reference the path in sym::dw::SourceCodeFile if it is made stable
  std::unordered_map<std::string, std::vector<std::shared_ptr<sym::dw::SourceCodeFile>>> mSourceCodeFiles;

  sym::AddressToCompilationUnitMap mAddressToCompileUnitMapping;
  std::unordered_map<int, Ref<sym::Value>> mValueObjectCache;

public:
  ObjectFile(std::string objfile_id, Path p, u64 size, const u8 *loaded_binary) noexcept;
  ~ObjectFile() noexcept;

  static std::shared_ptr<ObjectFile> CreateObjectFile(tc::SupervisorState *tc, const Path &path) noexcept;

  template <typename T>
  auto
  AlignedRequiredGetAtOffset(u64 offset) -> T *
  {
    MDB_ASSERT(offset < mSize, "offset out of bounds");
    MDB_ASSERT((offset % std::alignment_of<T>::value) == 0, "Alignment failure!");
    return (T *)(mLoadedBinary + offset);
  }

  constexpr bool
  IsFile(const Path &other) noexcept
  {
    return other == mObjectFilePath;
  }

  auto GetPathString() const noexcept -> const char *;
  const Elf *GetElf() const noexcept;
  auto GetUnwinder() noexcept -> sym::Unwinder *;
  auto GetObjectFileId() const noexcept -> std::string_view;
  auto GetFilePath() const noexcept -> const Path &;
  auto GetAddressRange() const noexcept -> AddressRange;
  auto HasReadLnpHeader(u64 offset) noexcept -> bool;
  auto GetLnpHeader(u64 offset) noexcept -> sym::dw::LNPHeader *;
  // This method may fail in inserting `header` - but it only does so because it was raced by another thread and
  // completed faster the caller must therefore delete `header` upon seeing `false` returned.
  auto SetLnpHeader(u64 offset, sym::dw::LNPHeader *header) noexcept -> bool;

  auto GetTypeStorage() noexcept -> NonNullPtr<TypeStorage>;
  auto GetElfSectionBytes(Elf *elf, u32 index) const noexcept -> u8 *;
  auto FindMinimalFunctionSymbol(std::string_view name, bool searchDynamic = false) noexcept
    -> std::optional<MinSymbol>;
  auto SearchMinimalSymbolFunctionInfo(AddrPtr pc) noexcept -> const MinSymbol *;
  auto FindMinimalObjectSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>;

  auto SetCompileUnitData(const std::vector<sym::dw::UnitData *> &unit_data) noexcept -> void;
  auto GetAllCompileUnits() noexcept -> std::span<sym::dw::UnitData *>;
  auto GetCompileUnitFromOffset(u64 offset) noexcept -> sym::dw::UnitData *;
  auto GetDebugInfoEntryReference(u64 offset) noexcept -> std::optional<sym::dw::DieReference>;
  auto GetDieReference(u64 offset) noexcept -> sym::dw::DieReference;
  auto GetNameIndex() noexcept -> sym::dw::ObjectFileNameIndex *;

  auto AddInitializedCompileUnits(std::span<sym::CompilationUnit *> new_cus) noexcept -> void;
  auto AddTypeUnits(std::span<sym::dw::UnitData *> type_units) noexcept -> void;
  auto AddSourceCodeFile(sym::dw::SourceCodeFile::Ref file) noexcept -> void;
  auto ReadDebugRanges(u64 sectionOffset) noexcept -> std::vector<AddressRange>;

  auto GetTypeUnit(u64 type_signature) noexcept -> sym::dw::UnitData *;
  auto GetTypeUnitTypeDebugInfoEntry(u64 type_signature) noexcept -> sym::dw::DieReference;

  auto GetSourceCodeFiles(std::string_view full_path) noexcept
    -> std::span<std::shared_ptr<sym::dw::SourceCodeFile>>;
  auto GetCompilationUnits() noexcept -> std::span<sym::CompilationUnit *>;

  auto InitializeDebugSymbolInfo() noexcept -> void;
  auto ParseELFSymbols(Elf64Header *header, std::vector<ElfSection> &&sections) noexcept -> void;

  auto InitializeMinimalSymbolLookup() noexcept -> void;

  auto FindCustomDataVisualizerFor(sym::Type &type) noexcept -> std::unique_ptr<sym::DebugAdapterSerializer>;
  static auto InitializeDataVisualizer(sym::Value &value) noexcept -> void;

  /**
   * Search the string tables of a object file, using regex pattern `regex_pattern`
   */
  auto SearchDebugSymbolStringTable(const std::string &regex) const noexcept -> std::vector<std::string>;

private:
  /**
   * Get the compilation units that *probably* span/cover the address of `programCounter`. When an object file
   * is loaded and initialized, the compilation units are mapped to using address ranges. Multiple compilation
   * units may have their range cover `programCounter`. It's up to the caller to figure out which CU is actually
   * the one they're interested in.
   */
  auto GetProbableCompilationUnits(AddrPtr programCounter) noexcept -> std::vector<sym::CompilationUnit *>;
  // TODO(simon): Implement something more efficient. For now, we do the absolute worst thing, but this problem is
  // uninteresting for now and not really important, as it can be fixed at any point in time.
  auto GetCompilationUnitsSpanningPC(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>;
};

class SymbolFile
{
  std::shared_ptr<ObjectFile> mObjectFile;
  tc::SupervisorState *mTraceeController{ nullptr };

public:
  using shr_ptr = std::shared_ptr<SymbolFile>;
  Immutable<std::string> mSymbolObjectFileId;
  Immutable<AddrPtr> mBaseAddress;
  Immutable<AddressRange> mPcBounds;

  SymbolFile(tc::SupervisorState *tc,
    std::string obj_id,
    std::shared_ptr<ObjectFile> &&binary,
    AddrPtr relocated_base) noexcept;

  static shr_ptr Create(
    tc::SupervisorState *tc, std::shared_ptr<ObjectFile> &&binary, AddrPtr relocated_base) noexcept;
  auto Copy(tc::SupervisorState &tc, AddrPtr relocated_base) const noexcept -> std::shared_ptr<SymbolFile>;
  auto GetUnitDataFromProgramCounter(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>;

  inline auto
  GetObjectFile() const noexcept -> ObjectFile *
  {
    return mObjectFile.get();
  }
  auto ContainsProgramCounter(AddrPtr pc) const noexcept -> bool;
  auto UnrelocateAddress(AddrPtr pc) const noexcept -> AddrPtr;

  auto GetLocals(tc::SupervisorState &tc, sym::Frame &frame) noexcept -> std::vector<Ref<sym::Value>>;

  auto GetVariables(tc::SupervisorState &tc, sym::Frame &frame, sym::VariableSet set) noexcept
    -> std::vector<Ref<sym::Value>>;
  auto GetCompilationUnits(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>;
  static auto GetStaticResolver(sym::Value &value) noexcept -> sym::IValueResolve *;
  auto ResolveVariable(const VariableContext &ctx, std::optional<u32> start, std::optional<u32> count) noexcept
    -> std::vector<Ref<sym::Value>>;

  auto LowProgramCounter() noexcept -> AddrPtr;
  auto HighProgramCounter() noexcept -> AddrPtr;

  auto GetMinimalFunctionSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>;
  auto SearchMinimalSymbolFunctionInfo(AddrPtr pc) noexcept -> const MinSymbol *;
  auto GetMinimalSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>;
  auto GetObjectFilePath() const noexcept -> Path;

  auto LookupFunctionBreakpointBySpec(const BreakpointSpecification &spec) noexcept
    -> std::vector<BreakpointLookup>;
  auto GetSupervisor() noexcept -> tc::SupervisorState *;
  auto GetTextSection() const noexcept -> const ElfSection *;

private:
  auto GetVariables(sym::FrameVariableKind variables_kind, tc::SupervisorState &tc, sym::Frame &frame) noexcept
    -> std::vector<Ref<sym::Value>>;
};

ObjectFile *mmap_objectfile(const tc::SupervisorState &tc, const Path &path) noexcept;
void object_file_unloader(ObjectFile *obj);
} // namespace mdb