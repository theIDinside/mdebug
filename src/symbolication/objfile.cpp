#include "objfile.h"
#include "../so_loading.h"
#include "./dwarf/name_index.h"
#include "dwarf.h"
#include "dwarf/die.h"
#include "supervisor.h"
#include "symbolication/block.h"
#include "symbolication/dwarf_defs.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/value_visualizer.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tasks/lnp.h"
#include "type.h"
#include "utils/enumerator.h"
#include "utils/logger.h"
#include "utils/worker_task.h"
#include "value.h"
#include <algorithm>
#include <iterator>
#include <regex>
#include <symbolication/dwarf/typeread.h>
#include <task.h>
#include <tracer.h>
#include <utility>
#include <utils/scoped_fd.h>

ParsedAuxiliaryVector
ParsedAuxiliaryVectorData(const tc::Auxv &aux) noexcept
{
  ParsedAuxiliaryVector result;
  for (const auto [id, value] : aux.vector) {
    switch (id) {
    case AT_PHDR:
      result.mProgramHeaderPointer = value;
      break;
    case AT_PHENT:
      result.mProgramHeaderEntrySize = value;
      break;
    case AT_PHNUM:
      result.mProgramHeaderCount = value;
      break;
    case AT_BASE:
      result.mInterpreterBaseAddress = value;
      break;
    case AT_ENTRY:
      result.mEntry = value;
      break;
    }
  }
  DBGLOG(core, "Auxiliary Vector: {{ interpreter: {}, program entry: {}, program headers: {} }}",
         result.mInterpreterBaseAddress, result.mEntry, result.mProgramHeaderPointer);
  return result;
}

ObjectFile::ObjectFile(std::string objfile_id, Path p, u64 size, const u8 *loaded_binary) noexcept
    : mObjectFilePath(std::move(p)), mObjectFileId(std::move(objfile_id)), mSize(size),
      mLoadedBinary(loaded_binary), mTypeStorage(TypeStorage::Create()), mMinimalFunctionSymbols{},
      mMinimalFunctionSymbolsSorted(), mMinimalObjectSymbols{}, mUnitDataWriteLock(), mCompileUnits(),
      mNameToDieIndex(std::make_unique<sym::dw::ObjectFileNameIndex>()), lnp_headers(nullptr),
      mCompileUnitWriteLock(), mCompilationUnits(), mAddressToCompileUnitMapping()
{
  ASSERT(size > 0, "Loaded Object File is invalid");
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

NonNullPtr<TypeStorage>
ObjectFile::GetTypeStorage() noexcept
{
  return NonNull(*mTypeStorage);
}

std::optional<MinSymbol>
ObjectFile::FindMinimalFunctionSymbol(std::string_view name) noexcept
{
  if (mMinimalFunctionSymbols.contains(name)) {
    auto &index = mMinimalFunctionSymbols[name];
    if (const auto symbol = mMinimalFunctionSymbolsSorted[index]; symbol.maybe_size > 0) {
      return symbol;
    }
  }
  return std::nullopt;
}

const MinSymbol *
ObjectFile::SearchMinimalSymbolFunctionInfo(AddrPtr pc) noexcept
{
  auto it = std::lower_bound(mMinimalFunctionSymbolsSorted.begin(), mMinimalFunctionSymbolsSorted.end(), pc,
                             [](auto &sym, AddrPtr addr) { return sym.StartPc() < addr; });
  if (it == std::end(mMinimalFunctionSymbolsSorted)) {
    return nullptr;
  }

  auto prev = (it == std::begin(mMinimalFunctionSymbolsSorted)) ? it : it - 1;
  if (prev->StartPc() <= pc && prev->EndPc() >= pc) {
    return prev.base();
  } else {
    return nullptr;
  }
}

std::optional<MinSymbol>
ObjectFile::FindMinimalObjectSymbol(std::string_view name) noexcept
{
  if (mMinimalObjectSymbols.contains(name)) {
    return mMinimalObjectSymbols[name];
  } else {
    return std::nullopt;
  }
}

void
ObjectFile::SetCompileUnitData(const std::vector<sym::dw::UnitData *> &unit_data) noexcept
{
  ASSERT(!unit_data.empty(), "Expected unit data to be non-empty");
  std::lock_guard lock(mUnitDataWriteLock);
  auto first_id = unit_data.front()->section_offset();
  const auto it =
    std::lower_bound(mCompileUnits.begin(), mCompileUnits.end(), first_id,
                     [](const sym::dw::UnitData *ptr, u64 id) { return ptr->section_offset() < id; });
  mCompileUnits.insert(it, unit_data.begin(), unit_data.end());
}

std::vector<sym::dw::UnitData *> &
ObjectFile::GetAllCompileUnits() noexcept
{
  return mCompileUnits;
}

sym::dw::UnitData *
ObjectFile::GetCompileUnitFromOffset(u64 offset) noexcept
{
  auto it = std::find_if(mCompileUnits.begin(), mCompileUnits.end(),
                         [&](sym::dw::UnitData *cu) { return cu->spans_across(offset); });
  if (it != std::end(mCompileUnits)) {
    return *it;
  } else {
    return nullptr;
  }
}

std::optional<sym::dw::DieReference>
ObjectFile::GetDebugInfoEntryReference(u64 offset) noexcept
{
  auto cu = GetCompileUnitFromOffset(offset);
  if (cu == nullptr) {
    return {};
  }
  auto die = cu->get_die(offset);
  if (die == nullptr) {
    return {};
  }

  return sym::dw::DieReference{cu, die};
}

sym::dw::DieReference
ObjectFile::GetDieReference(u64 offset) noexcept
{
  auto cu = GetCompileUnitFromOffset(offset);
  if (cu == nullptr) {
    return sym::dw::DieReference{nullptr, nullptr};
  }
  auto die = cu->get_die(offset);
  if (die == nullptr) {
    return sym::dw::DieReference{nullptr, nullptr};
  }

  return sym::dw::DieReference{cu, die};
}

sym::dw::ObjectFileNameIndex *
ObjectFile::GetNameIndex() noexcept
{
  return mNameToDieIndex.get();
}

sym::dw::LNPHeader *
ObjectFile::GetLineNumberProgramHeader(u64 offset) noexcept
{
  for (auto &header : *lnp_headers) {
    if (header.sec_offset == offset) {
      return &header;
    }
  }
  DBGLOG(core, "WARNING no LNP Header with id = 0x{:x}", offset);
  return nullptr;
}

void
ObjectFile::ReadLineNumberProgramHeaders() noexcept
{
  lnp_headers = sym::dw::read_lnp_headers(this);
  std::string path_buf{};
  for (auto &hdr : *lnp_headers) {
    ASSERT(!hdr.directories.empty(), "Directories for the LNP header must *NOT* be empty!");
    const auto build_path = std::filesystem::path{hdr.directories[0].path};
    for (const auto &[fullPath, _] : hdr.FileEntries()) {
      auto it = mSourceCodeFiles.find(fullPath);
      if (it != std::end(mSourceCodeFiles)) {
        it->second->AddNewLineNumberProgramHeader(&hdr);
      } else {
        std::vector<sym::dw::LNPHeader *> src_headers{};
        src_headers.push_back(&hdr);
        DBGLOG(core, "Adding source code file {}", fullPath);
        auto sourceCodeFile = std::make_shared<sym::dw::SourceCodeFile>(elf, fullPath);
        sourceCodeFile->AddNewLineNumberProgramHeader(&hdr);
        mSourceCodeFiles.emplace(fullPath, std::move(sourceCodeFile));
      }
    }
  }
}

// No synchronization needed, parsed 1, in 1 thread
std::span<sym::dw::LNPHeader>
ObjectFile::GetLineNumberProgramHeaders() noexcept
{
  if (lnp_headers) {
    return std::span{*lnp_headers};
  } else {
    ReadLineNumberProgramHeaders();
    return std::span{*lnp_headers};
  }
}

void
ObjectFile::AddInitializedCompileUnits(std::span<sym::CompilationUnit> new_cus) noexcept
{
  // TODO(simon): We do stupid sorting. implement something better optimized
  std::lock_guard lock(mCompileUnitWriteLock);
  mCompilationUnits.insert(mCompilationUnits.end(), std::make_move_iterator(new_cus.begin()),
                           std::make_move_iterator(new_cus.end()));
  std::sort(mCompilationUnits.begin(), mCompilationUnits.end(), sym::CompilationUnit::Sorter());

  DBG({
    if (!std::is_sorted(mCompilationUnits.begin(), mCompilationUnits.end(), sym::CompilationUnit::Sorter())) {
      for (const auto &cu : mCompilationUnits) {
        DBGLOG(core, "[cu dwarf offset=0x{:x}]: start_pc = {}, end_pc={}", cu.get_dwarf_unit()->section_offset(),
               cu.StartPc(), cu.EndPc());
      }
      PANIC("Dumped CU contents");
    }
  })
  mAddressToCompileUnitMapping.add_cus(new_cus);
}

void
ObjectFile::AddTypeUnits(std::span<sym::dw::UnitData *> tus) noexcept
{
  for (const auto tu : tus) {
    ASSERT(tu->header().get_unit_type() == DwarfUnitType::DW_UT_type, "Expected DWARF Unit Type but got {}",
           to_str(tu->header().get_unit_type()));
    mTypeToUnitDataMap[tu->header().type_signature()] = tu;
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
  ASSERT(typeunit != nullptr, "expected typeunit with signature 0x{:x}", type_signature);
  const auto type_die_cu_offset = typeunit->header().get_type_offset();
  const auto type_die_section_offset = typeunit->section_offset() + type_die_cu_offset;
  const auto &dies = typeunit->get_dies();
  for (const auto &d : dies) {
    if (d.section_offset == type_die_section_offset) {
      return sym::dw::DieReference{typeunit, &d};
    }
  }
  return {nullptr, nullptr};
}

std::vector<sym::CompilationUnit> &
ObjectFile::GetCompilationUnits() noexcept
{
  return mCompilationUnits;
}

SharedPtr<sym::dw::SourceCodeFile>
ObjectFile::GetSourceCodeFile(std::string_view fullpath) noexcept
{
  std::string key{fullpath};
  auto it = mSourceCodeFiles.find(key);
  if (it != std::end(mSourceCodeFiles)) {
    return it->second;
  }
  return nullptr;
}

std::vector<sym::dw::UnitData *>
ObjectFile::GetProbableCompilationUnits(AddrPtr programCounter) noexcept
{
  return mAddressToCompileUnitMapping.find_by_pc(programCounter);
}

// TODO(simon): Implement something more efficient. For now, we do the absolute worst thing, but this problem is
// uninteresting for now and not really important, as it can be fixed at any point in time.
std::vector<sym::CompilationUnit *>
ObjectFile::GetCompilationUnitsSpanningPC(AddrPtr pc) noexcept
{
  std::vector<sym::CompilationUnit *> result;
  auto unit_datas = mAddressToCompileUnitMapping.find_by_pc(pc);
  for (auto &src : GetCompilationUnits()) {
    for (auto *unit : unit_datas) {
      if (src.get_dwarf_unit() == unit) {
        result.push_back(&src);
      }
    }
  }
  return result;
}

auto
ObjectFile::GetRelocatedSourceCodeFiles(AddrPtr base,
                                        AddrPtr pc) noexcept -> std::vector<sym::dw::RelocatedSourceCodeFile>
{
  std::vector<sym::dw::RelocatedSourceCodeFile> result{};
  auto cus = GetCompilationUnitsSpanningPC(pc);
  const auto is_unique = [&](auto ptr) noexcept {
    return std::none_of(result.begin(), result.end(), [ptr](auto cmp) { return ptr->full_path == cmp.path(); });
  };
  for (auto cu : cus) {
    for (auto &src : cu->sources()) {
      ASSERT(src != nullptr, "source code file should not be null!");
      if (src->address_bounds().Contains(pc) && is_unique(src.get())) {
        result.emplace_back(base, src.get());
      }
    }
  }
  return result;
}

void
ObjectFile::InitializeDebugSymbolInfo(const sys::DwarfParseConfiguration &config) noexcept
{
  // First block of tasks need to finish before continuing with anything else.
  utils::TaskGroup cu_taskgroup("Compilation Unit Data");
  auto cu_work = sym::dw::UnitDataTask::create_jobs_for(this);
  cu_taskgroup.add_tasks(std::span{cu_work});
  cu_taskgroup.schedule_work().wait();
  ReadLineNumberProgramHeaders();

  if (config.eager_lnp_parse) {
    utils::TaskGroup lnp_tg("Line number programs");
    auto lnp_work = sym::dw::LineNumberProgramTask::create_jobs_for(this);
    lnp_tg.add_tasks(std::span{lnp_work});
    lnp_tg.schedule_work().wait();
  }

  utils::TaskGroup name_index_taskgroup("Name Indexing");
  auto ni_work = sym::dw::IndexingTask::create_jobs_for(this);
  name_index_taskgroup.add_tasks(std::span{ni_work});
  name_index_taskgroup.schedule_work().wait();
}

void
ObjectFile::AddMinimalElfSymbols(std::vector<MinSymbol> &&fn_symbols,
                                 std::unordered_map<std::string_view, MinSymbol> &&obj_symbols) noexcept
{
  mMinimalFunctionSymbolsSorted = std::move(fn_symbols);
  mMinimalObjectSymbols = std::move(obj_symbols);
  InitializeMinimalSymbolLookup();
}

void
ObjectFile::InitializeMinimalSymbolLookup() noexcept
{
  for (const auto &[index, sym] : utils::EnumerateView(mMinimalFunctionSymbolsSorted)) {
    mMinimalFunctionSymbols[sym.name] = Index{static_cast<u32>(index)};
  }
}

std::unique_ptr<sym::ValueVisualizer>
ObjectFile::FindCustomDataVisualizerFor(sym::Type &) noexcept
{
  return nullptr;
}

std::unique_ptr<sym::ValueResolver>
ObjectFile::FindCustomDataResolverFor(sym::Type &) noexcept
{
  return nullptr;
}

void
ObjectFile::InitializeDataVisualizer(std::shared_ptr<sym::Value> &value) noexcept
{
  if (value->HasVisualizer()) {
    return;
  }

  sym::Type &type = *value->GetType()->ResolveAlias();
  if (auto custom_visualiser = FindCustomDataVisualizerFor(type); custom_visualiser != nullptr) {
    return;
  }

  if (type.IsArrayType()) {
    value = sym::Value::WithVisualizer<sym::ArrayVisualizer>(std::move(value));
  } else if (type.IsPrimitive() || type.IsReference()) {
    value = sym::Value::WithVisualizer<sym::PrimitiveVisualizer>(std::move(value));
  } else {
    value = sym::Value::WithVisualizer<sym::DefaultStructVisualizer>(std::move(value));
  }
}

auto
ObjectFile::SearchDebugSymbolStringTable(const std::string &regex) const noexcept -> std::vector<std::string>
{
  // TODO(simon): Optimize. Regexing .debug_str in for instance libxul.so, takes 15 seconds (on O3, on -O0; it
  // takes 180 seconds)
  std::regex re{regex};
  if (elf->debug_str == nullptr) {
    return {};
  }

  std::string_view dbg_str{elf->debug_str->GetDataAs<const char>()};

  auto it = std::regex_iterator<std::string_view::iterator>{dbg_str.cbegin(), dbg_str.cend(), re};
  std::vector<std::string> results{};

  for (decltype(it) end; it != end; ++it) {
    results.push_back((*it).str());
  }

  return results;
}

auto
ObjectFile::SetBuildDirectory(u64 statementListOffset, const char *buildDirectory) noexcept -> void
{
  mLnpToBuildDirMapping.mMap[statementListOffset] = buildDirectory;
}

auto
ObjectFile::GetBuildDirForLineNumberProgram(u64 statementListOffset) noexcept -> const char *
{
  if (auto it = mLnpToBuildDirMapping.mMap.find(statementListOffset); it != std::end(mLnpToBuildDirMapping.mMap)) {
    return it->second;
  }
  return nullptr;
}

ObjectFile *
mmap_objectfile(const TraceeController &tc, const Path &path) noexcept
{
  if (!fs::exists(path)) {
    return nullptr;
  }

  auto fd = utils::ScopedFd::open_read_only(path);
  const auto addr = fd.mmap_file<u8>({}, true);
  const auto objfile =
    new ObjectFile{fmt::format("{}:{}", tc.TaskLeaderTid(), path.c_str()), path, fd.file_size(), addr};

  return objfile;
}

/* static */
std::shared_ptr<ObjectFile>
ObjectFile::CreateObjectFile(TraceeController *tc, const Path &path) noexcept
{
  if (!fs::exists(path)) {
    return nullptr;
  }

  auto fd = utils::ScopedFd::open_read_only(path);
  const auto addr = fd.mmap_file<u8>({}, true);
  const auto objfile = std::make_shared<ObjectFile>(fmt::format("{}:{}", tc->TaskLeaderTid(), path.c_str()), path,
                                                    fd.file_size(), addr);

  DBGLOG(core, "Parsing objfile {}", objfile->GetPathString());
  const auto header = objfile->AlignedRequiredGetAtOffset<Elf64Header>(0);
  ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0, "ELF Magic not correct, expected {} got {}",
         *(u32 *)(ELF_MAGIC), *(u32 *)(header->e_ident));
  std::vector<ElfSection> sectionData;
  sectionData.reserve(header->e_shnum);

  const auto sec_names_offset_hdr =
    objfile->AlignedRequiredGetAtOffset<Elf64_Shdr>(header->e_shoff + (header->e_shstrndx * header->e_shentsize));

  u64 min = UINTMAX_MAX;
  u64 max = 0;

  // good enough heuristic to determine mapped in ranges.
  for (auto i = 0; i < header->e_phnum; ++i) {
    auto phdr = objfile->AlignedRequiredGetAtOffset<Elf64_Phdr>(header->e_phoff + header->e_phentsize * i);
    if (phdr->p_type == PT_LOAD) {
      min = std::min(phdr->p_vaddr, min);
      const auto end = u64{phdr->p_vaddr + phdr->p_memsz};
      const auto align_adjust = u64{phdr->p_align - (end % phdr->p_align)};
      max = std::max(end + align_adjust, max);
    }
  }

  objfile->mUnrelocatedAddressBounds = AddressRange{.low = min, .high = max};
  auto sec_hdrs_offset = header->e_shoff;
  // parse sections
  for (auto i = 0; i < header->e_shnum; i++) {
    const auto sec_hdr = objfile->AlignedRequiredGetAtOffset<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    sectionData.push_back(ElfSection{
      .mSectionData = std::span{objfile->AlignedRequiredGetAtOffset<u8>(sec_hdr->sh_offset), sec_hdr->sh_size},
      .mName = objfile->AlignedRequiredGetAtOffset<const char>(sec_names_offset_hdr->sh_offset + sec_hdr->sh_name),
      .file_offset = sec_hdr->sh_offset,
      .address = sec_hdr->sh_addr,
    });
  }
  // ObjectFile is the owner of `Elf`
  objfile->elf = new Elf{header, std::move(sectionData)};
  Elf::ParseMinimalSymbol(objfile->elf, *objfile);
  objfile->unwinder = sym::ParseExceptionHeaderSection(objfile.get(), objfile->elf->GetSection(".eh_frame"));
  if (const auto section = objfile->elf->GetSection(".debug_frame"); section) {
    DBGLOG(core, ".debug_frame section found; parsing DWARF CFI section");
    sym::ParseDwarfDebugFrame(objfile->GetElf(), objfile->unwinder.get(), section);
  }

  if (objfile->elf->HasDWARF()) {
    objfile->InitializeDebugSymbolInfo(Tracer::Instance->getConfig().dwarf_config());
  }

  return objfile;
}

SymbolFile::SymbolFile(TraceeController *tc, std::string obj_id, std::shared_ptr<ObjectFile> &&binary,
                       AddrPtr relocated_base) noexcept
    : mObjectFile(std::move(binary)), mTraceeController(tc), mSymbolObjectFileId(std::move(obj_id)),
      mBaseAddress(relocated_base),
      mPcBounds(AddressRange::relocate(mObjectFile->mUnrelocatedAddressBounds, relocated_base))
{
}

SymbolFile::shr_ptr
SymbolFile::Create(TraceeController *tc, std::shared_ptr<ObjectFile> &&binary, AddrPtr relocated_base) noexcept
{
  ASSERT(binary != nullptr, "SymbolFile was provided no backing ObjectFile");

  return std::make_shared<SymbolFile>(tc, fmt::format("{}:{}", tc->TaskLeaderTid(), binary->GetPathString()),
                                      std::move(binary), relocated_base);
}

auto
SymbolFile::Copy(TraceeController &tc, AddrPtr relocated_base) const noexcept -> std::shared_ptr<SymbolFile>
{
  auto obj = mObjectFile;
  return SymbolFile::Create(&tc, std::move(obj), relocated_base);
}

auto
SymbolFile::GetUnitDataFromProgramCounter(AddrPtr pc) noexcept -> std::vector<sym::dw::UnitData *>
{
  return GetObjectFile()->GetProbableCompilationUnits(pc - mBaseAddress->get());
}

inline auto
SymbolFile::GetObjectFile() const noexcept -> ObjectFile *
{
  return mObjectFile.get();
}

auto
SymbolFile::ContainsProgramCounter(AddrPtr pc) const noexcept -> bool
{
  return mPcBounds->Contains(pc);
}

auto
SymbolFile::UnrelocateAddress(AddrPtr pc) const noexcept -> AddrPtr
{
  ASSERT(pc > mBaseAddress, "PC={} is below base address {}.", pc, mBaseAddress);
  return pc - mBaseAddress;
}

auto
SymbolFile::RegisterValueResolver(std::shared_ptr<sym::Value> &value) noexcept -> void
{
  // TODO(simon): For now this "infrastructure" just hardcodes support for custom visualization of C-strings
  //   the idea, is that we later on should be able to extend this to plug in new resolvers & printers/visualizers.
  //   remember: we don't just lump everything into "pretty printer"; we have distinct ideas about how to resolve
  //   values and how to display them, which *is* the issue with GDB's pretty printers
  auto type = value->GetType()->ResolveAlias();

  if (auto resolver = GetObjectFile()->FindCustomDataResolverFor(*type); resolver != nullptr) {
    value->SetResolver(std::move(resolver));
    return;
  }
  auto layout_type = type->TypeDescribingLayoutOfThis();

  const auto array_type = type->IsArrayType();
  if (type->IsReference() && !array_type) {
    if (layout_type->IsCharType()) {
      DBGLOG(core, "[datviz]: setting cstring resolver for value");
      auto ptr = std::make_unique<sym::CStringResolver>(this, value, value->GetType());
      value->SetResolver(std::move(ptr));
    } else {
      DBGLOG(core, "[datviz]: setting pointer resolver for value");
      value->SetResolver(std::make_unique<sym::ReferenceResolver>(this, value, value->GetType()));
    }
    return;
  }

  // todo: again, this is hardcoded, which is counter to the whole idea here.
  if (array_type) {
    DBGLOG(core, "[datviz]: setting array resolver for value");
    auto layout_type = type->TypeDescribingLayoutOfThis();
    auto ptr = std::make_unique<sym::ArrayResolver>(this, layout_type, type->ArraySize(), value->Address());
    value->SetResolver(std::move(ptr));
    value = sym::Value::WithVisualizer<sym::ArrayVisualizer>(std::move(value));
    return;
  }
}

auto
SymbolFile::GetVariables(TraceeController &tc, sym::Frame &frame,
                         sym::VariableSet set) noexcept -> std::vector<ui::dap::Variable>
{
  auto symbolInformation = frame.MaybeGetFullSymbolInfo();
  if(!symbolInformation) {
    return {};
  }
  if (!symbolInformation->IsResolved()) {
    sym::dw::FunctionSymbolicationContext sym_ctx{*this->GetObjectFile(), frame};
    sym_ctx.process_symbol_information();
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
SymbolFile::GetCompilationUnits(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>
{
  return mObjectFile->GetCompilationUnitsSpanningPC(pc - *mBaseAddress);
}

auto
SymbolFile::GetSourceCodeFiles(AddrPtr pc) noexcept -> std::vector<sym::dw::RelocatedSourceCodeFile>
{
  return mObjectFile->GetRelocatedSourceCodeFiles(mBaseAddress, pc);
}

auto
SymbolFile::ResolveVariable(const VariableContext &ctx, std::optional<u32> start,
                            std::optional<u32> count) noexcept -> std::vector<ui::dap::Variable>
{
  auto value = ctx.get_maybe_value();
  if (value == nullptr) {
    DBGLOG(core, "WARNING expected variable reference {} had no data associated with it.", ctx.id);
    return {};
  }
  auto type = value->GetType();
  if (!type->IsResolved()) {
    sym::dw::TypeSymbolicationContext ts_ctx{*GetObjectFile(), *type};
    ts_ctx.resolve_type();
  }

  auto value_resolver = value->GetResolver();
  if (value_resolver != nullptr) {
    auto variables = value_resolver->Resolve(*ctx.tc, start, count);
    std::vector<ui::dap::Variable> result{};

    for (auto &var : variables) {
      GetObjectFile()->InitializeDataVisualizer(var);
      RegisterValueResolver(var);
      const auto new_ref = var->GetType()->IsPrimitive() ? 0 : Tracer::Instance->clone_from_var_context(ctx);
      if (new_ref > 0) {
        ctx.t->cache_object(new_ref, var);
      }
      result.push_back(ui::dap::Variable{static_cast<int>(new_ref), var});
    }

    return result;
  } else {
    std::vector<ui::dap::Variable> result{};
    result.reserve(type->MemberFields().size());

    for (auto &mem : type->MemberFields()) {
      auto member_value = std::make_shared<sym::Value>(mem.name, const_cast<sym::Field &>(mem),
                                                       value->mMemoryContentsOffsets, value->TakeMemoryReference());
      GetObjectFile()->InitializeDataVisualizer(member_value);
      RegisterValueResolver(member_value);
      const auto new_ref =
        member_value->GetType()->IsPrimitive() ? 0 : Tracer::Instance->clone_from_var_context(ctx);
      if (new_ref > 0) {
        ctx.t->cache_object(new_ref, member_value);
      }
      result.push_back(ui::dap::Variable{static_cast<int>(new_ref), std::move(member_value)});
    }
    return result;
  }
}

auto
SymbolFile::LowProgramCounter() noexcept -> AddrPtr
{
  return mBaseAddress + GetObjectFile()->mUnrelocatedAddressBounds.low;
}

auto
SymbolFile::HighProgramCounter() noexcept -> AddrPtr
{
  return mBaseAddress + GetObjectFile()->mUnrelocatedAddressBounds.high;
}

auto
SymbolFile::GetMinimalFunctionSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>
{
  return mObjectFile->FindMinimalFunctionSymbol(name);
}

auto
SymbolFile::SearchMinimalSymbolFunctionInfo(AddrPtr pc) noexcept -> const MinSymbol *
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
SymbolFile::GetSupervisor() noexcept -> TraceeController *
{
  return mTraceeController;
}

auto
SymbolFile::GetTextSection() const noexcept -> const ElfSection *
{
  return mObjectFile->elf->GetSection(".text");
}

auto
SymbolFile::LookupBreakpointBySpec(const FunctionBreakpointSpec &spec) noexcept -> std::vector<BreakpointLookup>
{

  std::vector<MinSymbol> matching_symbols;
  std::vector<BreakpointLookup> result{};

  auto obj = GetObjectFile();
  std::vector<std::string> search_for{};
  if (spec.is_regex) {
    const auto start = std::chrono::high_resolution_clock::now();
    search_for = obj->SearchDebugSymbolStringTable(spec.name);
    const auto elapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
        .count();
    DBGLOG(core, "regex searched {} in {}us", obj->GetPathString(), elapsed);
  } else {
    search_for = {spec.name};
  }

  for (const auto &n : search_for) {
    auto ni = obj->GetNameIndex();
    ni->for_each_fn(n, [&](const sym::dw::DieNameReference &ref) {
      auto die_ref = ref.cu->get_cu_die_ref(ref.die_index);
      auto low_pc = die_ref.read_attribute(Attribute::DW_AT_low_pc);
      if (low_pc) {
        const auto addr = low_pc->address();
        matching_symbols.emplace_back(n, addr, 0);
        DBGLOG(core, "[{}][cu=0x{:x}, die=0x{:x}] found fn {} at low_pc of {}", obj->GetPathString(),
               die_ref.GetUnitData()->section_offset(), die_ref.GetDie()->section_offset, n, addr);
      }
    });
  }

  Set<AddrPtr> bps_set{};
  for (const auto &sym : matching_symbols) {
    const auto relocatedAddress = sym.address + mBaseAddress;
    if (!bps_set.contains(relocatedAddress)) {
      auto srcs = GetSourceCodeFiles(sym.address);
      for (auto src : srcs) {
        if (src.address_bounds().Contains(relocatedAddress)) {
          if (const auto lte = src.FindLineTableEntry(relocatedAddress);
              lte && !bps_set.contains(relocatedAddress)) {
            result.emplace_back(relocatedAddress, LocationSourceInfo{src.path(), lte->line, u32{lte->column}});
            bps_set.insert(sym.address);
          }
        }
      }
    }
  }

  for (const auto &n : search_for) {
    if (auto s =
          obj->FindMinimalFunctionSymbol(n).transform([&](const auto &sym) { return sym.address + mBaseAddress; });
        s.has_value() && !bps_set.contains(s.value())) {
      result.emplace_back(s.value(), std::nullopt);
      bps_set.insert(s.value());
    }
  }

  return result;
}

auto
SymbolFile::GetVariables(sym::FrameVariableKind variables_kind, TraceeController &tc,
                         sym::Frame &frame) noexcept -> std::vector<ui::dap::Variable>
{
  std::vector<ui::dap::Variable> result{};
  switch (variables_kind) {
  case sym::FrameVariableKind::Arguments:
    result.reserve(frame.FrameParameterCounts());
    break;
  case sym::FrameVariableKind::Locals:
    result.reserve(frame.FrameLocalVariablesCount());
    break;
  }

  std::vector<NonNullPtr<const sym::Symbol>> relevantSymbols;
  frame.GetInitializedVariables(variables_kind, relevantSymbols);

  for(const sym::Symbol& symbol : relevantSymbols) {
    const auto ref = symbol.mType->IsPrimitive() ? 0 : Tracer::Instance->new_key();
    if (ref == 0 && !symbol.mType->IsResolved()) {
      sym::dw::TypeSymbolicationContext ts_ctx{*this->GetObjectFile(), symbol.mType};
      ts_ctx.resolve_type();
    }

    auto value_object = sym::MemoryContentsObject::CreateFrameVariable(tc, frame.mTask, NonNull(frame),
                                                                         const_cast<sym::Symbol &>(symbol), true);
    GetObjectFile()->InitializeDataVisualizer(value_object);
    RegisterValueResolver(value_object);

    if (ref > 0) {
      Tracer::Instance->set_var_context({&tc, frame.mTask->ptr, frame.GetSymbolFile(),
                                         static_cast<u32>(frame.FrameId()), static_cast<u16>(ref),
                                         ContextType::Variable});
      frame.mTask.mut()->cache_object(ref, value_object);
    }
    result.push_back(ui::dap::Variable{static_cast<int>(ref), std::move(value_object)});
  }
  return result;
}