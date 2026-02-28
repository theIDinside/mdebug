/** LICENSE TEMPLATE */
#include "objfile.h"

// mdb
#include <bp.h>
#include <common.h>
#include <jobs/dwarf_unit_data.h>
#include <jobs/index_die_names.h>
#include <lib/arena_allocator.h>
#include <mdbjs/mdbjs.h>
#include <mdbjs/value_resolver_registry.h>
#include <symbolication/block.h>
#include <symbolication/callstack.h>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/dwarf/name_index.h>
#include <symbolication/dwarf/typeread.h>
#include <symbolication/dwarf_attribute_value.h>
#include <symbolication/dwarf_defs.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/elf_symbols.h>
#include <symbolication/type.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <task.h>
#include <tracer.h>
#include <utils/enumerator.h>
#include <utils/logger.h>
#include <utils/scope_defer.h>
#include <utils/scoped_fd.h>
#include <utils/task_list.h>
#include <utils/todo.h>
#include <utils/worker_task.h>

// std
#include <algorithm>
#include <cstddef>
#include <iterator>
#include <regex>
#include <unordered_set>
#include <utility>

// system
#include <elf.h>
#include <immintrin.h>

namespace mdb {
template <typename T> using Set = std::unordered_set<T>;

ObjectFile::ObjectFile(std::string objfile_id, Path p, u64 size, const u8 *loaded_binary) noexcept
    : mObjectFilePath(std::move(p)), mObjectFileId(std::move(objfile_id)), mSize(size),
      mLoadedBinary(loaded_binary), mTypeStorage(TypeStorage::Create()),
      mNameToDieIndex(std::make_unique<sym::dw::ObjectFileNameIndex>())
{
  MDB_ASSERT(size > 0, "Loaded Object File is invalid");
}

ObjectFile::~ObjectFile() noexcept
{
  delete elf;
  munmap((void *)mLoadedBinary, mSize);
}

const char *
ObjectFile::GetPathString() const noexcept
{
  return mObjectFilePath.c_str();
}

const Elf *
ObjectFile::GetElf() const noexcept
{
  return elf;
}

sym::Unwinder *
ObjectFile::GetUnwinder() noexcept
{
  return unwinder.get();
}

std::string_view
ObjectFile::GetObjectFileId() const noexcept
{
  return mObjectFileId;
}

const Path &
ObjectFile::GetFilePath() const noexcept
{
  return mObjectFilePath;
}

AddressRange
ObjectFile::GetAddressRange() const noexcept
{
  return mUnrelocatedAddressBounds;
}

auto
ObjectFile::HasReadLnpHeader(u64 offset) noexcept -> bool
{
  std::lock_guard lock(mLnpHeaderMutex);
  return mLineNumberProgramHeaders.contains(offset);
}

auto
ObjectFile::GetLnpHeader(u64 offset) noexcept -> sym::dw::LNPHeader *
{
  return mLineNumberProgramHeaders[offset];
}

auto
ObjectFile::SetLnpHeader(u64 offset, sym::dw::LNPHeader *header) noexcept -> bool
{
  std::lock_guard lock(mLnpHeaderMutex);
  if (mLineNumberProgramHeaders.contains(offset)) {
    return false;
  }
  mLineNumberProgramHeaders[offset] = header;
  return true;
}

NonNullPtr<TypeStorage>
ObjectFile::GetTypeStorage() noexcept
{
  return NonNull(*mTypeStorage);
}

std::optional<MinSymbol>
ObjectFile::FindMinimalFunctionSymbol(std::string_view name, bool searchDynamic) noexcept
{
  for (const auto &symbol : mMinimalFunctionSymbolsSorted) {
    if (symbol.name.contains(name)) {
      DBGLOG(
        core, "[{}]: Returning symbol that contains name '{}': {}", mObjectFilePath.c_str(), name, symbol.name);
      return symbol;
    }
  }

  if (searchDynamic) {
    for (const auto &symbol : mMinimalDynamicFunctionSymbolsSorted) {
      if (symbol.name.contains(name)) {
        DBGLOG(core,
          "[{}]: Returning dynamic symbol that contains name '{}': {}",
          mObjectFilePath.c_str(),
          name,
          symbol.name);
        return symbol;
      }
    }
  }

  return std::nullopt;
}

const MinSymbol *
ObjectFile::SearchMinimalSymbolFunctionInfo(AddrPtr pc) noexcept
{
  auto it = std::lower_bound(
    mMinimalFunctionSymbolsSorted.begin(), mMinimalFunctionSymbolsSorted.end(), pc, [](auto &sym, AddrPtr addr) {
      return sym.StartPc() < addr;
    });
  if (it == std::end(mMinimalFunctionSymbolsSorted)) {
    return nullptr;
  }

  auto prev = (it == std::begin(mMinimalFunctionSymbolsSorted)) ? it : it - 1;
  if (prev->StartPc() <= pc && prev->EndPc() >= pc) {
    return prev.base();
  }
  return nullptr;
}

std::optional<MinSymbol>
ObjectFile::FindMinimalObjectSymbol(std::string_view name) noexcept
{
  if (mMinimalObjectSymbols.contains(name)) {
    return mMinimalObjectSymbols[name];
  }
  return std::nullopt;
}

void
ObjectFile::SetCompileUnitData(const std::vector<sym::dw::UnitData *> &unit_data) noexcept
{
  using sym::dw::UnitData;
  MDB_ASSERT(!unit_data.empty(), "Expected unit data to be non-empty");
  std::lock_guard lock(mUnitDataWriteLock);
  mCompileUnits.insert(mCompileUnits.begin(), unit_data.begin(), unit_data.end());
  std::ranges::sort(
    mCompileUnits, [](UnitData *a, UnitData *b) { return a->SectionOffset() < b->SectionOffset(); });
}

std::span<sym::dw::UnitData *>
ObjectFile::GetAllCompileUnits() noexcept
{
  return mCompileUnits;
}

sym::dw::UnitData *
ObjectFile::GetCompileUnitFromOffset(u64 offset) noexcept
{

  const auto it = std::lower_bound(
    mCompileUnits.begin(), mCompileUnits.end(), offset, [](sym::dw::UnitData *compUnit, u64 offset) {
      return compUnit->SectionOffset() + compUnit->UnitSize() < offset;
    });

  if (it != std::end(mCompileUnits)) {
    MDB_ASSERT((*it)->SpansAcrossOffset(offset), "compilation unit does not span 0x{:x}", offset);
    return *it;
  }
  return nullptr;
}

std::optional<sym::dw::DieReference>
ObjectFile::GetDebugInfoEntryReference(u64 offset) noexcept
{
  sym::dw::UnitData *cu = GetCompileUnitFromOffset(offset);
  if (cu == nullptr) {
    return {};
  }
  const sym::dw::DieMetaData *die = cu->GetDebugInfoEntry(offset);
  if (die == nullptr) {
    return {};
  }

  return sym::dw::DieReference{ cu, die };
}

sym::dw::DieReference
ObjectFile::GetDieReference(u64 offset) noexcept
{
  sym::dw::UnitData *cu = GetCompileUnitFromOffset(offset);
  if (cu == nullptr) {
    return sym::dw::DieReference{ nullptr, nullptr };
  }
  const sym::dw::DieMetaData *die = cu->GetDebugInfoEntry(offset);
  if (die == nullptr) {
    return sym::dw::DieReference{ nullptr, nullptr };
  }

  return sym::dw::DieReference{ cu, die };
}

sym::dw::ObjectFileNameIndex *
ObjectFile::GetNameIndex() noexcept
{
  return mNameToDieIndex.get();
}

void
ObjectFile::AddInitializedCompileUnits(std::span<sym::CompilationUnit *> newCompileUnits) noexcept
{
  // TODO(simon): We do stupid sorting. implement something better optimized
  PROFILE_SCOPE_ARGS(
    "ObjectFile::AddInitializedCompileUnits", "symbolication", PEARG("comp_units", newCompileUnits.size()));
  std::lock_guard lock(mCompileUnitWriteLock);
  mCompilationUnits.insert(mCompilationUnits.end(), newCompileUnits.begin(), newCompileUnits.end());
  std::ranges::sort(mCompilationUnits, sym::CompilationUnit::Sorter());

  for (sym::CompilationUnit *compileUnit : newCompileUnits) {
    const auto sources = compileUnit->sources();
    std::unordered_set<sym::dw::SourceCodeFile *> added;
    for (const auto &[fileIndex, src] : sources) {
      if (!added.contains(src.get())) {
        mSourceCodeFiles[std::string{ src->mFullPath.StringView() }].push_back(src);
        added.insert(src.get());
      }
    }
  }

  DBG({
    if (!std::ranges::is_sorted(mCompilationUnits, sym::CompilationUnit::Sorter())) {
      for (const auto cu : mCompilationUnits) {
        DBGLOG(core,
          "[cu dwarf offset={}]: start_pc = {}, end_pc={}",
          cu->GetDwarfUnitData()->SectionOffset(),
          cu->StartPc(),
          cu->EndPc());
      }
      PANIC("Dumped CU contents");
    }
  })
  mAddressToCompileUnitMapping.AddCompilationUnits(newCompileUnits);
}

void
ObjectFile::AddTypeUnits(std::span<sym::dw::UnitData *> typeUnits) noexcept
{
  for (sym::dw::UnitData *tu : typeUnits) {
    MDB_ASSERT(tu->GetHeader().GetUnitType() == DwarfUnitType::DW_UT_type,
      "Expected DWARF Unit Type but got {}",
      to_str(tu->GetHeader().GetUnitType()));
    mTypeToUnitDataMap[tu->GetHeader().TypeSignature()] = tu;
  }
}

void
ObjectFile::AddSourceCodeFile(sym::dw::SourceCodeFile::Ref file) noexcept
{
  mSourceCodeFiles[std::string{ file->mFullPath.StringView() }].push_back(std::move(file));
}

const uint64_t *
FindRangeListNullTerminator(const uint64_t *data, std::size_t size)
{

  if (size < 2) {
    return nullptr; // Need at least two elements
  }

  std::size_t i = 0;
  constexpr std::size_t stride = 4;
  std::size_t simd_end = size - (size % stride);

  for (; i < simd_end; i += stride) {
    // Load 4 uint64_t values
    __m256i values = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&data[i]));

    // Compare elements with 0
    __m256i zero = _mm256_setzero_si256();
    __m256i cmp = _mm256_cmpeq_epi64(values, zero);

    // Extract bitmask (each comparison result is 1 bit)
    const unsigned mask = static_cast<unsigned>(_mm256_movemask_pd(_mm256_castsi256_pd(cmp)));
    const unsigned masked = (mask & 0b1111);

    // Count trailing 0s
    const unsigned trailing_zeros = std::countr_zero(masked);
    // Count trailing 1s in the shifted mask
    unsigned trailing_ones = std::countr_one((masked) >> trailing_zeros);

    if (trailing_ones >= 2) {
      return &data[i + trailing_zeros];
    }
  }

  // Fallback: Process remaining elements normally
  for (; i < size - 1; ++i) {
    if (data[i] == 0 && data[i + 1] == 0) {
      return &data[i];
    }
  }

  return nullptr;
}

static u32
ReadAligned(const u64 *start, const u64 *end, std::vector<AddressRange> &result) noexcept
{

  for (auto it = start; it < end; it += 2) {
    const auto a = *it;
    const auto b = *(it + 1);
    if (a == 0) {
      if (b == 0) {
        return result.size();
      } else {
        continue;
      }
    }
    result.push_back({ a, b });
  }
  return result.size();
}

static u32
ReadUnAligned(const u8 *start, const u8 *end, std::vector<AddressRange> &result) noexcept
{
  auto it = start;
  alignas(32) u64 buf[32];
  while (it < end) {
    const auto bytesCount = std::min<size_t>(sizeof(u64) * std::size(buf), end - it);
    std::memcpy(buf, it, bytesCount);

    for (auto i = 0u; i < std::size(buf); i += 2) {
      if (buf[i] == 0) {
        if (buf[i + 1] == 0) {
          return result.size();
        }
      }
      result.push_back({ .low = buf[i], .high = buf[i + 1] });
    }
    it += bytesCount;
  }
  return result.size();
}

std::vector<AddressRange>
ObjectFile::ReadDebugRanges(u64 sectionOffset) noexcept
{
  if (!elf->mDebugRanges) {
    return {};
  }
  if (elf->mDebugRanges->Size() <= sectionOffset) {
    return {};
  }

  std::vector<AddressRange> result;
  auto ptr = elf->mDebugRanges->GetDataAsIfAligned<u64>(sectionOffset);
  if (ptr) {
    auto count = elf->mDebugRanges->mSectionData->size() / sizeof(u64);
    ReadAligned(ptr, (elf->mDebugRanges->GetDataAs<u64>().data() + count), result);
    return result;
  } else {
    ReadUnAligned(elf->mDebugRanges->begin() + sectionOffset, elf->mDebugRanges->end(), result);
    return result;
  }
}

sym::dw::UnitData *
ObjectFile::GetTypeUnit(u64 type_signature) noexcept
{
  if (auto it = mTypeToUnitDataMap.find(type_signature); it != std::end(mTypeToUnitDataMap)) {
    return it->second;
  } else {
    return nullptr;
  }
}

sym::dw::DieReference
ObjectFile::GetTypeUnitTypeDebugInfoEntry(u64 type_signature) noexcept
{
  auto typeunit = GetTypeUnit(type_signature);
  MDB_ASSERT(typeunit != nullptr, "expected typeunit with signature 0x{:x}", type_signature);
  const auto typeDieCuOffset = typeunit->GetHeader().GetTypeOffset();
  const auto typeDieSectionOffset = typeunit->SectionOffset() + typeDieCuOffset;
  const auto &dies = typeunit->GetDies();
  for (const auto &d : dies) {
    if (d.mSectionOffset == typeDieSectionOffset) {
      return sym::dw::DieReference{ typeunit, &d };
    }
  }
  return { nullptr, nullptr };
}

std::span<sym::CompilationUnit *>
ObjectFile::GetCompilationUnits() noexcept
{
  return mCompilationUnits;
}

std::span<SharedPtr<sym::dw::SourceCodeFile>>
ObjectFile::GetSourceCodeFiles(std::string_view fullpath) noexcept
{
  std::string key{ fullpath };
  auto it = mSourceCodeFiles.find(key);
  if (it != std::end(mSourceCodeFiles)) {
    return it->second;
  }
  return {};
}

std::vector<sym::CompilationUnit *>
ObjectFile::GetProbableCompilationUnits(AddrPtr programCounter) noexcept
{
  return mAddressToCompileUnitMapping.find_by_pc(programCounter);
}

// TODO(simon): Implement something more efficient. For now, we do the absolute worst thing, but this problem is
// uninteresting for now and not really important, as it can be fixed at any point in time.
std::vector<sym::CompilationUnit *>
ObjectFile::GetCompilationUnitsSpanningPC(AddrPtr pc) const noexcept
{
  return mAddressToCompileUnitMapping.find_by_pc(pc);
}

void
ObjectFile::InitializeDebugSymbolInfo() noexcept
{
  // First block of tasks need to finish before continuing with anything else.
  mdb::TaskGroup compUnitTaskGroup("Compilation Unit Data");
  auto compUnitWork = sym::dw::UnitDataTask::CreateParsingJobs(this, compUnitTaskGroup.GetTemporaryAllocator());
  compUnitTaskGroup.AddTasks(std::span{ compUnitWork });
  compUnitTaskGroup.ScheduleWork().wait();

  mdb::TaskGroup nameIndexTaskGroup("Name Indexing");
  auto nameIndexWork = sym::dw::IndexingTask::CreateIndexingJobs(this, nameIndexTaskGroup.GetTemporaryAllocator());
  nameIndexTaskGroup.AddTasks(std::span{ nameIndexWork });
  nameIndexTaskGroup.ScheduleWork().wait();
}

void
ObjectFile::ParseELFSymbols(Elf64Header *header, std::vector<ElfSection> &&sections) noexcept
{
  elf = new Elf{ header, std::move(sections) };

  const auto parseSymbols = [this](ElfSec stringTable,
                              ElfSec symbolTable,
                              std::vector<MinSymbol> &fnSymbols,
                              StringViewMap<MinSymbol> &objectSymbols) {
    const ElfSection *strtab = elf->GetSection(stringTable);
    const ElfSection *sec = elf->GetSection(symbolTable);

    if (strtab && sec) {
      auto symbols = sec->GetDataAs<Elf64_Sym>();
      for (const auto &symbol : symbols) {
        if (ELF64_ST_TYPE(symbol.st_info) == STT_FUNC) {
          const std::string_view name = strtab->GetCString(symbol.st_name);
          fnSymbols.emplace_back(name, AddrPtr{ symbol.st_value }, u64{ symbol.st_size });
        } else if (ELF64_ST_TYPE(symbol.st_info) == STT_OBJECT) {
          const std::string_view name = strtab->GetCString(symbol.st_name);
          objectSymbols[name] =
            MinSymbol{ .name = name, .address = symbol.st_value, .maybe_size = symbol.st_size };
        }
      }
      // TODO(simon): Again; sorting after insertion may not be as good as actually sorting while inserting.
      constexpr auto cmp = [](const auto &a, const auto &b) -> bool { return a.address < b.address; };
      std::sort(fnSymbols.begin(), fnSymbols.end(), cmp);
    } else {
      DBGLOG(core, "[warning]: No .symtab for {}", GetPathString());
    }
  };

  parseSymbols(ElfSec::StringTable, ElfSec::SymbolTable, mMinimalFunctionSymbolsSorted, mMinimalObjectSymbols);

  parseSymbols(ElfSec::DynamicStringTable,
    ElfSec::DynamicSymbolTable,
    mMinimalDynamicFunctionSymbolsSorted,
    mMinimalDynamicObjectSymbols);

  // Initialize minimal symbols so they can be looked up in a hashmap
  for (const auto &[index, sym] : Enumerate<u32>(mMinimalFunctionSymbolsSorted)) {
    mMinimalFunctionSymbols[sym.name] = Index{ index };
  }

  for (const auto &[index, sym] : Enumerate(mMinimalDynamicFunctionSymbolsSorted)) {
    mMinimalDynamicFunctionSymbols[sym.name] = Index{ static_cast<u32>(index) };
  }
}

std::unique_ptr<sym::DebugAdapterSerializer>
ObjectFile::FindCustomDataVisualizerFor(sym::Type &) noexcept
{
  return nullptr;
}

/* static */
void
ObjectFile::SetSerializerFor(sym::Value &value) noexcept
{
  if (!value.IsValidValue()) {
    value.SetDapSerializer(Tracer::GetDataResolver<sym::InvalidValueSerializer>());
  }
  if (value.HasVisualizer()) {
    return;
  }

  sym::Type &type = *value.GetType()->ResolveAlias();

  if (type.IsArrayType()) {
    value.SetDapSerializer(Tracer::GetDataResolver<sym::ArraySerializer>());
  } else if (type.IsPrimitive() || type.IsReference()) {
    value.SetDapSerializer(Tracer::GetDataResolver<sym::PrimitiveSerializer>());
  } else {
    value.SetDapSerializer(Tracer::GetDataResolver<sym::DefaultStructSerializer>());
  }
}

auto
ObjectFile::SearchDebugSymbolStringTableParallelized(const std::string &regex) const noexcept
  -> std::vector<std::string>
{
  // TODO(simon): Optimize. Regexing .debug_str in for instance libxul.so, takes 15 seconds (on O3, on -O0; it
  // takes 180 seconds)
  std::regex re{ regex };
  if (elf->mDebugStr == nullptr) {
    return {};
  }

  std::string_view stringTableView{ elf->mDebugStr->GetDataAs<const char>() };

  auto jobSize = std::min<size_t>(stringTableView.size(), MegaByte(2));
  std::vector<std::pair<size_t, size_t>> positions;
  size_t previous = 0;
  for (size_t i = jobSize; i < stringTableView.size(); i += jobSize) {
    auto innerIndex = std::min(i, stringTableView.size());
    while (innerIndex < stringTableView.size() && stringTableView[innerIndex] != 0) {
      ++innerIndex;
    }
    positions.emplace_back(previous, innerIndex - previous);
    previous = innerIndex + 1;
  }

  // Split work into parallel tasks for large debug string sections
  auto taskList = TaskList::Create<std::vector<std::string>>(TaskList::Unordered);

  for (const auto &[start, count] : positions) {
    std::string_view strSection = stringTableView.substr(start, count);
    taskList->Add([strSection, re]() {
      std::vector<std::string> results{};
      auto it = std::regex_iterator<std::string_view::iterator>{ strSection.cbegin(), strSection.cend(), re };
      for (decltype(it) end; it != end; ++it) {
        const char *strPointer = strSection.data() + it->position();
        results.emplace_back(strPointer);
      }
      return results;
    });
  }

  // Collect results from all parallel tasks as they complete
  std::vector<std::string> results{};
  for (const auto &taskResults : taskList->Commit()) {
    if (!taskResults.empty()) {
      std::ranges::move(taskResults, std::back_inserter(results));
    }
  }

  return results;
}

auto
ObjectFile::SearchDebugSymbolStringTable(const std::string &regexString) const noexcept -> std::vector<std::string>
{
  // TODO(simon): Optimize. Regexing .debug_str in for instance libxul.so, takes 15 seconds (on O3, on -O0; it
  // takes 180 seconds)
  if (elf->mDebugStr == nullptr) {
    return {};
  }

  return SearchDebugSymbolStringTableParallelized(regexString);
}

auto
ObjectFile::ForEachStructOrClassType(
  std::string_view pattern, bool exactPattern, const std::function<bool(sym::Type *type)> &onEachType) -> void
{
  // Step 1: Search ELF string sections for matching strings using regex
  std::vector<std::string> matchedStrings;

  const auto ownedPattern = std::string{ pattern.data(), pattern.size() };

  if (!exactPattern) {
    matchedStrings = SearchDebugSymbolStringTable(ownedPattern);
  } else {
    matchedStrings.emplace_back(pattern);
  }

  if (matchedStrings.empty()) {
    return;
  }

  auto *nameIndex = GetNameIndex();
  std::vector<sym::dw::DieNameReference> dieReferences;

  std::unordered_set<sym::dw::UnitData *> compUnitsNeedingLoad;

  for (const auto &matchedName : matchedStrings) {
    nameIndex->ForEachType(matchedName, [&](const sym::dw::DieNameReference &ref) {
      if (!ref.cu->HasLoadedDies()) {
        compUnitsNeedingLoad.insert(ref.cu);
      }
      dieReferences.push_back(ref);
    });
  }

  if (compUnitsNeedingLoad.size() > 16) {
    DBGLOG(core,
      "Needing more than 16 compilation units who are not loaded into memory. Parallel task spawning not yet "
      "implemented.");
  }

  auto typeStorage = GetTypeStorage();
  std::unordered_set<sym::Type *> foundTypes;

  for (const auto &dieRef : dieReferences) {
    auto dieReference = dieRef.cu->GetDieByCacheIndex(dieRef.die_index);
    const auto *die = dieReference.GetDie();

    if (!die) {
      continue;
    }

    const auto tag = die->mTag;
    switch (tag) {
    case DwarfTag::DW_TAG_structure_type:
    case DwarfTag::DW_TAG_class_type:
      break;
    default:
      continue;
    }

    const u64 dieOffset = die->mSectionOffset;
    sym::Type *type = typeStorage->FindTypeByOffset(dieOffset);

    if (type != nullptr) {
      if (foundTypes.insert(type).second) {
        if (!onEachType(type)) {
          return;
        }
      }
    }
  }
}

auto
ObjectFile::ForEachTypeMatching(
  std::string_view pattern, bool exactPattern, const std::function<void(sym::Type *type)> &onEachType) -> void
{
  std::vector<std::string> matchedStrings;

  const auto ownedPattern = std::string{ pattern.data(), pattern.size() };

  if (!exactPattern) {
    matchedStrings = SearchDebugSymbolStringTable(ownedPattern);
  } else {
    matchedStrings.emplace_back(pattern);
  }

  if (matchedStrings.empty()) {
    return;
  }

  auto *nameIndex = GetNameIndex();
  std::vector<sym::dw::DieNameReference> dieReferences;

  for (const auto &matchedName : matchedStrings) {
    nameIndex->ForEachType(
      matchedName, [&](const sym::dw::DieNameReference &ref) { dieReferences.push_back(ref); });
  }

  auto typeStorage = GetTypeStorage();
  std::unordered_set<sym::Type *> foundTypes; // Use set to avoid duplicates

  for (const auto &dieRef : dieReferences) {
    auto dieReference = dieRef.cu->GetDieByCacheIndex(dieRef.die_index);
    const auto *die = dieReference.GetDie();

    if (!die) {
      continue;
    }

    const u64 dieOffset = die->mSectionOffset;
    sym::Type *type = typeStorage->FindTypeByOffset(dieOffset);

    if (type != nullptr) {
      if (foundTypes.insert(type).second) {
        onEachType(type);
      }
    }
  }
}

/* static */
std::shared_ptr<ObjectFile>
ObjectFile::GetOrCreateObjectFile(const Path &path) noexcept
{
  if (auto objectFile = Tracer::LookupSymbolFile(path); objectFile) {
    return objectFile;
  }

  if (!fs::exists(path)) {
    DBGLOG(core, "Object file path not found={}", path.c_str());
    return nullptr;
  }

  auto fd = mdb::ScopedFd::OpenFileReadOnly(path);
  const auto *addr = fd.MmapFile<u8>({}, true);
  const auto objfile = std::make_shared<ObjectFile>(std::format("{}", path.c_str()), path, fd.FileSize(), addr);

  DBGLOG(core, "Parsing objfile {}", objfile->GetPathString());
  auto *header = objfile->AlignedRequiredGetAtOffset<Elf64Header>(0);
  MDB_ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0,
    "ELF Magic not correct, expected {} got {}",
    *(u32 *)(ELF_MAGIC),
    *(u32 *)(header->e_ident));
  std::vector<ElfSection> sectionData;
  sectionData.reserve(header->e_shnum);

  const auto *sectionNamesOffsetHeader = objfile->AlignedRequiredGetAtOffset<Elf64_Shdr>(
    header->e_shoff + (static_cast<Elf64_Off>(header->e_shstrndx * header->e_shentsize)));

  u64 min = UINTMAX_MAX;
  u64 max = 0;

  // good enough heuristic to determine mapped in ranges.
  for (auto i = 0; i < header->e_phnum; ++i) {
    auto *programHeader =
      objfile->AlignedRequiredGetAtOffset<Elf64_Phdr>(header->e_phoff + (header->e_phentsize * i));
    if (programHeader->p_type == PT_LOAD) {
      min = std::min(programHeader->p_vaddr, min);
      const auto end = u64{ programHeader->p_vaddr + programHeader->p_memsz };
      const auto align_adjust = u64{ programHeader->p_align - (end % programHeader->p_align) };
      max = std::max(end + align_adjust, max);
    }
  }

  objfile->mUnrelocatedAddressBounds = AddressRange{ .low = min, .high = max };
  auto sec_hdrs_offset = header->e_shoff;
  // parse sections
  for (auto i = 0; i < header->e_shnum; i++) {
    const auto *sectionHeader = objfile->AlignedRequiredGetAtOffset<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    sectionData.push_back(ElfSection{
      .mSectionData =
        std::span{ objfile->AlignedRequiredGetAtOffset<u8>(sectionHeader->sh_offset), sectionHeader->sh_size },
      .mName = objfile->AlignedRequiredGetAtOffset<const char>(
        sectionNamesOffsetHeader->sh_offset + sectionHeader->sh_name),
      .file_offset = sectionHeader->sh_offset,
      .address = sectionHeader->sh_addr,
    });
  }
  // ObjectFile is the owner of `Elf`
  objfile->ParseELFSymbols(header, std::move(sectionData));

  auto unwinder = sym::ParseExceptionHeaderSection(objfile.get(), objfile->elf->GetSection(".eh_frame"));
  if (unwinder) {
    objfile->unwinder = std::move(unwinder);
  } else {
    // Create null unwinder. Probably likely that this (debug built - for release built objects everything goes out
    // the window) binary object doesn't have code in it.
    /// FIXME:(simon) We should probably verify that the SO doesn't have executable section/code. However, we don't
    /// support any unwinder techniques but the ones that solely rely on .eh_frame and .debug_frame so at the
    /// momement, *iff* the object would have a .text section (that's non-empty), we wouldn't be able to unwind any
    /// frames in it any how.
    objfile->unwinder = std::make_unique<sym::Unwinder>(nullptr);
  }
  if (const auto *section = objfile->elf->GetSection(".debug_frame"); section) {
    DBGLOG(core, ".debug_frame section found; parsing DWARF CFI section");
    sym::ParseDwarfDebugFrame(objfile->GetElf(), objfile->unwinder.get(), section);
  }

  if (objfile->elf->HasDWARF()) {
    objfile->InitializeDebugSymbolInfo();
  }

  Tracer::CacheObjectFile(objfile);

  return objfile;
}

SymbolFile::SymbolFile(
  Pid processId, std::string obj_id, std::shared_ptr<ObjectFile> &&binary, AddrPtr relocated_base) noexcept
    : mObjectFile(std::move(binary)), mProcessId(processId), mSymbolObjectFileId(std::move(obj_id)),
      mBaseAddress(relocated_base),
      mPcBounds(AddressRange::relocate(mObjectFile->mUnrelocatedAddressBounds, relocated_base))
{
}

SymbolFile::shr_ptr
SymbolFile::Create(Pid processId, std::shared_ptr<ObjectFile> &&binary, AddrPtr relocated_base) noexcept
{
  MDB_ASSERT(binary != nullptr, "SymbolFile was provided no backing ObjectFile");

  return std::make_shared<SymbolFile>(
    processId, std::format("{}:{}", processId, binary->GetPathString()), std::move(binary), relocated_base);
}

auto
SymbolFile::Copy(Pid processId, AddrPtr relocated_base) const noexcept -> std::shared_ptr<SymbolFile>
{
  auto obj = mObjectFile;
  return SymbolFile::Create(processId, std::move(obj), relocated_base);
}

auto
SymbolFile::GetUnitDataFromProgramCounter(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>
{
  return mObjectFile->GetProbableCompilationUnits(pc - mBaseAddress->GetRaw());
}

auto
SymbolFile::ContainsProgramCounter(AddrPtr pc) const noexcept -> bool
{
  return mPcBounds->Contains(pc);
}

auto
SymbolFile::UnrelocateAddress(AddrPtr pc) const noexcept -> AddrPtr
{
  MDB_ASSERT(pc > mBaseAddress, "PC={} is below base address {}.", pc, mBaseAddress);
  return pc - mBaseAddress;
}

auto
SymbolFile::GetLocals(tc::SupervisorState &tc, sym::Frame &frame) noexcept -> std::vector<Ref<sym::Value>>
{
  return GetVariables(tc, frame, sym::VariableSet::Locals);
}

auto
SymbolFile::GetVariables(tc::SupervisorState &tc, sym::Frame &frame, sym::VariableSet set) noexcept
  -> std::vector<Ref<sym::Value>>
{
  auto *symbolInformation = frame.MaybeGetFullSymbolInfo();
  if (!symbolInformation) {
    return {};
  }
  if (!symbolInformation->IsResolved()) {
    sym::dw::FunctionSymbolicationContext sym_ctx{ *this->GetObjectFile(), frame };
    sym_ctx.ProcessSymbolInformation();
  }

  switch (set) {
  case sym::VariableSet::Arguments: {
    return GetVariables(sym::FrameVariableKind::Arguments, tc, frame);
  }
  case sym::VariableSet::Locals: {
    return GetVariables(sym::FrameVariableKind::Locals, tc, frame);
  }
  case sym::VariableSet::Static:
  case sym::VariableSet::Global:
    TODO("Static or global variables request not yet supported.");
    break;
  }
  return {};
}

auto
SymbolFile::GetCompilationUnits(AddrPtr pc) const noexcept -> std::vector<sym::CompilationUnit *>
{
  return mObjectFile->GetCompilationUnitsSpanningPC(pc - *mBaseAddress);
}

/* static */
sym::IValueContentsResolver *
SymbolFile::GetStaticResolver(sym::Value &value) noexcept
{
  // TODO(simon): For now this "infrastructure" just hardcodes support for custom visualization of C-strings
  //   the idea, is that we later on should be able to extend this to plug in new resolvers & printers/visualizers.
  //   remember: we don't just lump everything into "pretty printer"; we have distinct ideas about how to resolve
  //   values and how to display them, which *is* the issue with GDB's pretty printers
  sym::Type *type = value.GetType()->ResolveAlias();

  sym::Type *layoutType = type->TypeDescribingLayoutOfThis();

  const auto arrayType = type->IsArrayType();
  if (type->IsReference() && !arrayType) {
    if (layoutType->IsCharType()) {
      return Tracer::GetResolver<sym::ResolveCString>();
    }
    return Tracer::GetResolver<sym::ResolveReference>();
  }

  // todo: again, this is hardcoded, which is counter to the whole idea here.
  if (arrayType) {
    return Tracer::GetResolver<sym::ResolveArray>();
  }
  return nullptr;
}

// static
auto
SymbolFile::ResolveVariable(
  const VariableContext &ctx, std::optional<u32> start, std::optional<u32> count) noexcept
  -> std::vector<Ref<sym::Value>>
{
  auto value = ctx.GetValue();
  if (value == nullptr) {
    DBGLOG(core, "WARNING expected variable reference {} had no data associated with it.", ctx.mId);
    return {};
  }

  sym::Type *type = value->EnsureTypeResolved()->SkipJunk();

  js::ResolverRegistry *registry = js::Scripting::GetResolverRegistry();
  sym::IValueContentsResolver *resolver = registry->GetResolver(type);

  if (!resolver) {
    resolver = GetStaticResolver(*value);
  }
  DBGLOG(core, "Found resolver for type {}: {}, members={}", type->mName, (void *)resolver, type->MembersCount());
  if (resolver != nullptr) {
    return resolver->Resolve(ctx, { .start = start, .count = count });
  }
  std::vector<Ref<sym::Value>> result{};
  result.reserve(type->MemberFields().size());

  for (const sym::Field &memberField : type->MemberFields()) {
    auto variableContext = memberField.mType->IsPrimitive() ? VariableContext::CloneFrom(0, ctx)
                                                            : Tracer::CloneFromVariableContext(ctx);
    auto vId = variableContext->mId;
    auto memberVariable = Ref<sym::Value>::MakeShared(std::move(variableContext),
      memberField.mName,
      const_cast<sym::Field &>(memberField),
      value->mMemoryContentsOffsets,
      value->TakeMemoryReference());
    ObjectFile::SetSerializerFor(*memberVariable);
    if (vId > 0) {
      ctx.mTask->CacheValueObject(vId, memberVariable);
    }
    result.push_back(std::move(memberVariable));
  }
  return result;
}

auto
SymbolFile::LowProgramCounter() const noexcept -> AddrPtr
{
  return mBaseAddress + GetObjectFile()->mUnrelocatedAddressBounds.low;
}

auto
SymbolFile::HighProgramCounter() const noexcept -> AddrPtr
{
  return mBaseAddress + GetObjectFile()->mUnrelocatedAddressBounds.high;
}

auto
SymbolFile::GetMinimalFunctionSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>
{
  return mObjectFile->FindMinimalFunctionSymbol(name);
}

auto
SymbolFile::SearchMinimalSymbolFunctionInfo(AddrPtr pc) const noexcept -> const MinSymbol *
{
  return GetObjectFile()->SearchMinimalSymbolFunctionInfo(pc - *mBaseAddress);
}

auto
SymbolFile::GetMinimalSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>
{
  return mObjectFile->FindMinimalObjectSymbol(name);
}

auto
SymbolFile::GetObjectFilePath() const noexcept -> Path
{
  return mObjectFile->mObjectFilePath;
}

auto
SymbolFile::GetId() const noexcept -> Pid
{
  return mProcessId;
}

auto
SymbolFile::GetTextSection() const noexcept -> const ElfSection *
{
  return mObjectFile->elf->GetSection(".text");
}

void
SymbolFile::ForEachTypeMatching(
  std::string_view pattern, bool exactPattern, const std::function<void(sym::Type *type)> &onEachType) const
{
  GetObjectFile()->ForEachTypeMatching(pattern, exactPattern, onEachType);
}

auto
SymbolFile::LookupFunctionBreakpointBySpec(const BreakpointSpecification &bpSpec) const noexcept
  -> std::vector<BreakpointLookup>
{
  MDB_ASSERT(bpSpec.mKind == DapBreakpointType::function, "required type=function");
  std::vector<MinSymbol> matchingSymbols;
  std::vector<BreakpointLookup> result{};

  ObjectFile *obj = GetObjectFile();
  std::vector<std::string> searchFor{};
  const auto &spec = *bpSpec.uFunction;
  if (spec.mIsRegex) {
    const auto start = std::chrono::high_resolution_clock::now();
    searchFor = obj->SearchDebugSymbolStringTable(spec.mName);
    const auto elapsed = MicroSecondsSince(start);
    DBGLOG(core, "regex searched {} in {}us", obj->GetPathString(), elapsed);
  } else {
    searchFor = { spec.mName };
  }

  for (const auto &n : searchFor) {
    sym::dw::ObjectFileNameIndex *ni = obj->GetNameIndex();
    ni->ForEachFn(n, [&](const sym::dw::DieNameReference &ref) {
      auto dieReference = ref.cu->GetDieByCacheIndex(ref.die_index);
      auto lowPc = dieReference.ReadAttribute(Attribute::DW_AT_low_pc);
      if (lowPc) {
        const auto addr = lowPc->AsAddress();
        matchingSymbols.emplace_back(n, addr, 0);
        DBGLOG(core,
          "[{}][cu={}, die=0x{:x}] found fn {} at low_pc of {}",
          obj->GetPathString(),
          dieReference.GetUnitData()->SectionOffset(),
          dieReference.GetDie()->mSectionOffset,
          n,
          AddrPtr{ addr });
      }
    });
  }

  Set<AddrPtr> bpsSet{};
  for (const auto &sym : matchingSymbols) {
    const auto relocatedAddress = sym.address + mBaseAddress;
    if (!bpsSet.contains(relocatedAddress)) {
      for (sym::CompilationUnit *cu : GetCompilationUnits(relocatedAddress)) {
        const auto [sourceFile, lineEntry] = cu->GetLineTableEntry(sym.address);
        if (sourceFile && lineEntry) {
          result.emplace_back(relocatedAddress,
            LocationSourceInfo{ .mSourceFile = sourceFile->mFullPath.StringView(),
              .mLineNumber = lineEntry->line,
              .mColumnNumber = u32{ lineEntry->column } });
          bpsSet.insert(relocatedAddress);
          break;
        }
      }
    }
  }

  for (const auto &n : searchFor) {
    if (auto s =
          obj->FindMinimalFunctionSymbol(n).transform([&](const auto &sym) { return sym.address + mBaseAddress; });
      s.has_value() && !bpsSet.contains(s.value())) {
      result.emplace_back(s.value(), std::nullopt);
      bpsSet.insert(s.value());
    }
  }

  return result;
}

auto
SymbolFile::GetVariables(sym::FrameVariableKind variablesKind, tc::SupervisorState &tc, sym::Frame &frame) noexcept
  -> std::vector<Ref<sym::Value>>
{
  PROFILE_SCOPE("SymbolFile::GetVariables", logging::kSymbolication);
  std::vector<Ref<sym::Value>> result{};
  switch (variablesKind) {
  case sym::FrameVariableKind::Arguments:
    result.reserve(frame.FrameParameterCounts());
    break;
  case sym::FrameVariableKind::Locals:
    result.reserve(frame.FrameLocalVariablesCount());
    break;
  }

  std::vector<NonNullPtr<const sym::Symbol>> relevantSymbols;
  frame.GetInitializedVariables(variablesKind, relevantSymbols);

  for (const sym::Symbol &symbol : relevantSymbols) {

    if (symbol.mType->IsPrimitive() && !symbol.mType->IsResolved()) {
      sym::dw::TypeSymbolicationContext symbolicationContext{ *this->GetObjectFile(), symbol.mType };
      symbolicationContext.ResolveType();
    }

    auto variableValue =
      sym::MemoryContentsObject::CreateFrameVariable(tc, frame, const_cast<sym::Symbol &>(symbol), true);
    ObjectFile::SetSerializerFor(*variableValue);

    if (const auto id = variableValue->ReferenceId(); id > 0) {
      variableValue->RegisterContext();
    }
    result.push_back(std::move(variableValue));
  }
  return result;
}
} // namespace mdb