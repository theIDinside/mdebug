#include "objfile.h"
#include "../so_loading.h"
#include "./dwarf/name_index.h"
#include "dwarf.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "supervisor.h"
#include "symbolication/block.h"
#include "symbolication/dwarf/lnp.h"
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

ObjectFile::ObjectFile(std::string objfile_id, Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), objfile_id(std::move(objfile_id)), size(size), loaded_binary(loaded_binary),
      types(std::make_unique<TypeStorage>(*this)), minimal_fn_symbols{}, min_fn_symbols_sorted(),
      minimal_obj_symbols{}, unit_data_write_lock(), dwarf_units(),
      name_to_die_index(std::make_unique<sym::dw::ObjectFileNameIndex>(this)), parsed_lte_write_lock(),
      line_table(), lnp_headers(nullptr),
      parsed_ltes(std::make_shared<std::unordered_map<u64, sym::dw::ParsedLineTableEntries>>()), cu_write_lock(),
      comp_units(), addr_cu_map()
{
  ASSERT(size > 0, "Loaded Object File is invalid");
}

ObjectFile::~ObjectFile() noexcept
{
  delete elf;
  munmap((void *)loaded_binary, size);
}

u64
ObjectFile::get_offset(u8 *ptr) const noexcept
{
  ASSERT(ptr > loaded_binary, "Attempted to take address before {:p} with {:p}", (void *)loaded_binary,
         (void *)ptr);
  ASSERT((u64)(ptr - loaded_binary) < size, "Pointer is outside of bounds of 0x{:x} .. {:x}",
         (std::uintptr_t)loaded_binary, (std::uintptr_t)(loaded_binary + *size))
  return ptr - loaded_binary;
}

AddrPtr
ObjectFile::text_section_offset() const noexcept
{
  return elf->get_section(".text")->address;
}

std::optional<MinSymbol>
ObjectFile::get_min_fn_sym(std::string_view name) noexcept
{
  if (minimal_fn_symbols.contains(name)) {
    auto &index = minimal_fn_symbols[name];
    if (const auto symbol = min_fn_symbols_sorted[index]; symbol.maybe_size > 0) {
      return symbol;
    }
  }
  return std::nullopt;
}

const MinSymbol *
ObjectFile::search_minsym_fn_info(AddrPtr pc) noexcept
{
  auto it = std::lower_bound(min_fn_symbols_sorted.begin(), min_fn_symbols_sorted.end(), pc,
                             [](auto &sym, AddrPtr addr) { return sym.start_pc() < addr; });
  if (it == std::end(min_fn_symbols_sorted)) {
    return nullptr;
  }

  auto prev = (it == std::begin(min_fn_symbols_sorted)) ? it : it - 1;
  if (prev->start_pc() <= pc && prev->end_pc() >= pc) {
    return prev.base();
  } else {
    return nullptr;
  }
}

std::optional<MinSymbol>
ObjectFile::get_min_obj_sym(std::string_view name) noexcept
{
  if (minimal_obj_symbols.contains(name)) {
    return minimal_obj_symbols[name];
  } else {
    return std::nullopt;
  }
}

void
ObjectFile::set_unit_data(const std::vector<sym::dw::UnitData *> &unit_data) noexcept
{
  ASSERT(!unit_data.empty(), "Expected unit data to be non-empty");
  std::lock_guard lock(unit_data_write_lock);
  auto first_id = unit_data.front()->section_offset();
  const auto it =
    std::lower_bound(dwarf_units.begin(), dwarf_units.end(), first_id,
                     [](const sym::dw::UnitData *ptr, u64 id) { return ptr->section_offset() < id; });
  dwarf_units.insert(it, unit_data.begin(), unit_data.end());
}

std::vector<sym::dw::UnitData *> &
ObjectFile::compilation_units() noexcept
{
  return dwarf_units;
}

sym::dw::UnitData *
ObjectFile::get_cu_from_offset(u64 offset) noexcept
{
  auto it = std::find_if(dwarf_units.begin(), dwarf_units.end(),
                         [&](sym::dw::UnitData *cu) { return cu->spans_across(offset); });
  if (it != std::end(dwarf_units)) {
    return *it;
  } else {
    return nullptr;
  }
}

std::optional<sym::dw::DieReference>
ObjectFile::get_die_reference(u64 offset) noexcept
{
  auto cu = get_cu_from_offset(offset);
  if (cu == nullptr) {
    return {};
  }
  auto die = cu->get_die(offset);
  if (die == nullptr) {
    return {};
  }

  return sym::dw::DieReference{cu, die};
}

sym::dw::DieReference ObjectFile::GetDieReference(u64 offset) noexcept {
  auto cu = get_cu_from_offset(offset);
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
ObjectFile::name_index() noexcept
{
  return name_to_die_index.get();
}

sym::dw::LNPHeader *
ObjectFile::get_lnp_header(u64 offset) noexcept
{
  for (auto &header : *lnp_headers) {
    if (header.sec_offset == offset) {
      return &header;
    }
  }
  TODO_FMT("handle requests of line table headers that aren't yet parsed (offset={})", offset);
}

void
ObjectFile::read_lnp_headers() noexcept
{
  lnp_headers = sym::dw::read_lnp_headers(elf);
  std::string path_buf{};
  for (auto &hdr : *lnp_headers) {
    ASSERT(!hdr.directories.empty(), "Directories for the LNP header must *NOT* be empty!");
    const auto build_path = std::filesystem::path{hdr.directories[0].path};
    for (const auto &[fullPath, _] : hdr.FileEntries()) {
      auto it = lnp_source_code_files.find(fullPath);
      if (it != std::end(lnp_source_code_files)) {
        it->second->add_header(&hdr);
      } else {
        std::vector<sym::dw::LNPHeader *> src_headers{};
        src_headers.push_back(&hdr);
        DBGLOG(core, "Adding source code file {}", fullPath);
        lnp_source_code_files.emplace(
          fullPath, std::make_shared<sym::dw::SourceCodeFile>(elf, fullPath, std::move(src_headers)));
      }
    }
  }
  init_lnp_storage(*lnp_headers);
}

// No synchronization needed, parsed 1, in 1 thread
std::span<sym::dw::LNPHeader>
ObjectFile::get_lnp_headers() noexcept
{
  if (lnp_headers) {
    return std::span{*lnp_headers};
  } else {
    read_lnp_headers();
    return std::span{*lnp_headers};
  }
}

// Synchronization needed - parsed by multiple threads and results registered asynchronously + in parallel
void
ObjectFile::add_parsed_ltes(const std::span<sym::dw::LNPHeader> &headers,
                            std::vector<sym::dw::ParsedLineTableEntries> &&parsed_ltes) noexcept
{
  std::lock_guard lock(parsed_lte_write_lock);
  ASSERT(headers.size() == parsed_ltes.size(), "headers != parsed_lte count!");
  auto h = headers.begin();
  auto p = std::make_move_iterator(parsed_ltes.begin());
  auto &stored = *this->parsed_ltes;
  for (; h != std::end(headers); h++, p++) {
    stored.emplace(h->sec_offset, std::move(*p));
  }
}

void
ObjectFile::init_lnp_storage(const std::span<sym::dw::LNPHeader> &headers)
{
  std::lock_guard lock(parsed_lte_write_lock);
  parsed_ltes->reserve(headers.size());
  for (const auto &header : headers) {
    parsed_ltes->emplace(header.sec_offset, sym::dw::ParsedLineTableEntries{});
  }
}

sym::dw::ParsedLineTableEntries &
ObjectFile::get_plte(u64 offset) noexcept
{
  return (*parsed_ltes)[offset];
}

void
ObjectFile::add_initialized_cus(std::span<sym::CompilationUnit> new_cus) noexcept
{
  // TODO(simon): We do stupid sorting. implement something better optimized
  std::lock_guard lock(cu_write_lock);
  comp_units.insert(comp_units.end(), std::make_move_iterator(new_cus.begin()),
                    std::make_move_iterator(new_cus.end()));
  std::sort(comp_units.begin(), comp_units.end(), sym::CompilationUnit::Sorter());

  DBG({
    if (!std::is_sorted(comp_units.begin(), comp_units.end(), sym::CompilationUnit::Sorter())) {
      for (const auto &cu : comp_units) {
        DBGLOG(core, "[cu dwarf offset=0x{:x}]: start_pc = {}, end_pc={}", cu.get_dwarf_unit()->section_offset(),
               cu.start_pc(), cu.end_pc());
      }
      PANIC("Dumped CU contents");
    }
  })
  addr_cu_map.add_cus(new_cus);
}

void
ObjectFile::add_type_units(std::span<sym::dw::UnitData *> tus) noexcept
{
  for (const auto tu : tus) {
    ASSERT(tu->header().get_unit_type() == DwarfUnitType::DW_UT_type, "Expected DWARF Unit Type but got {}",
           to_str(tu->header().get_unit_type()));
    type_units[tu->header().type_signature()] = tu;
  }
}

sym::dw::UnitData *
ObjectFile::get_type_unit(u64 type_signature) noexcept
{
  if (auto it = type_units.find(type_signature); it != std::end(type_units)) {
    return it->second;
  } else {
    return nullptr;
  }
}

sym::dw::DieReference
ObjectFile::get_type_unit_type_die(u64 type_signature) noexcept
{
  auto typeunit = get_type_unit(type_signature);
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
ObjectFile::source_units() noexcept
{
  return comp_units;
}

SharedPtr<sym::dw::SourceCodeFile>
ObjectFile::get_source_file(std::string_view fullpath) noexcept
{
  std::string key{fullpath};
  auto it = lnp_source_code_files.find(key);
  if (it != std::end(lnp_source_code_files)) {
    return it->second;
  }
  return nullptr;
}

std::vector<sym::dw::UnitData *>
ObjectFile::get_cus_from_pc(AddrPtr pc) noexcept
{
  return addr_cu_map.find_by_pc(pc);
}

// TODO(simon): Implement something more efficient. For now, we do the absolute worst thing, but this problem is
// uninteresting for now and not really important, as it can be fixed at any point in time.
std::vector<sym::CompilationUnit *>
ObjectFile::get_source_infos(AddrPtr pc) noexcept
{
  std::vector<sym::CompilationUnit *> result;
  auto unit_datas = addr_cu_map.find_by_pc(pc);
  for (auto &src : source_units()) {
    for (auto *unit : unit_datas) {
      if (src.get_dwarf_unit() == unit) {
        result.push_back(&src);
      }
    }
  }
  return result;
}

auto
ObjectFile::relocated_get_source_code_files(AddrPtr base,
                                            AddrPtr pc) noexcept -> std::vector<sym::dw::RelocatedSourceCodeFile>
{
  std::vector<sym::dw::RelocatedSourceCodeFile> result{};
  auto cus = get_source_infos(pc);
  const auto is_unique = [&](auto ptr) noexcept {
    return std::none_of(result.begin(), result.end(), [ptr](auto cmp) { return ptr->full_path == cmp.path(); });
  };
  for (auto cu : cus) {
    for (auto src : cu->sources()) {
      ASSERT(src != nullptr, "source code file should not be null!");
      if (src->address_bounds().contains(pc) && is_unique(src.get())) {
        result.emplace_back(base, src.get());
      }
    }
  }
  return result;
}

void
ObjectFile::initial_dwarf_setup(const sys::DwarfParseConfiguration &config) noexcept
{
  // First block of tasks need to finish before continuing with anything else.
  utils::TaskGroup cu_taskgroup("Compilation Unit Data");
  auto cu_work = sym::dw::UnitDataTask::create_jobs_for(this);
  cu_taskgroup.add_tasks(std::span{cu_work});
  cu_taskgroup.schedule_work().wait();
  read_lnp_headers();

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
ObjectFile::add_elf_symbols(std::vector<MinSymbol> &&fn_symbols,
                            std::unordered_map<std::string_view, MinSymbol> &&obj_symbols) noexcept
{
  min_fn_symbols_sorted = std::move(fn_symbols);
  minimal_obj_symbols = std::move(obj_symbols);
  init_minsym_name_lookup();
}

void
ObjectFile::init_minsym_name_lookup() noexcept
{
  for (const auto &[index, sym] : utils::EnumerateView(min_fn_symbols_sorted)) {
    minimal_fn_symbols[sym.name] = Index{static_cast<u32>(index)};
  }
}

std::unique_ptr<sym::ValueVisualizer>
ObjectFile::find_custom_visualizer(sym::Type &) noexcept
{
  return nullptr;
}

std::unique_ptr<sym::ValueResolver>
ObjectFile::find_custom_resolver(sym::Type &) noexcept
{
  return nullptr;
}

void
ObjectFile::init_visualizer(std::shared_ptr<sym::Value> &value) noexcept
{
  if (value->has_visualizer()) {
    return;
  }

  sym::Type &type = *value->type()->resolve_alias();
  if (auto custom_visualiser = find_custom_visualizer(type); custom_visualiser != nullptr) {
    return;
  }

  if (type.is_array_type()) {
    value = sym::Value::WithVisualizer<sym::ArrayVisualizer>(std::move(value));
  } else if (type.is_primitive() || type.is_reference()) {
    value = sym::Value::WithVisualizer<sym::PrimitiveVisualizer>(std::move(value));
  } else {
    value = sym::Value::WithVisualizer<sym::DefaultStructVisualizer>(std::move(value));
  }
}

auto
ObjectFile::regex_search(const std::string &regex_pattern) const noexcept -> std::vector<std::string>
{
  // TODO(simon): Optimize. Regexing .debug_str in for instance libxul.so, takes 15 seconds (on O3, on -O0; it
  // takes 180 seconds)
  std::regex re{regex_pattern};
  if (elf->debug_str == nullptr) {
    return {};
  }
  std::string_view dbg_str{(const char *)elf->debug_str->begin(), elf->debug_str->size()};

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
    new ObjectFile{fmt::format("{}:{}", tc.get_task_leader(), path.c_str()), path, fd.file_size(), addr};

  return objfile;
}

std::shared_ptr<ObjectFile>
CreateObjectFile(TraceeController *tc, const Path &path) noexcept
{
  if (!fs::exists(path)) {
    return nullptr;
  }

  auto fd = utils::ScopedFd::open_read_only(path);
  const auto addr = fd.mmap_file<u8>({}, true);
  const auto objfile = std::make_shared<ObjectFile>(fmt::format("{}:{}", tc->get_task_leader(), path.c_str()),
                                                    path, fd.file_size(), addr);

  DBGLOG(core, "Parsing objfile {}", objfile->path->c_str());
  const auto header = objfile->get_at_offset<Elf64Header>(0);
  ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0, "ELF Magic not correct, expected {} got {}",
         *(u32 *)(ELF_MAGIC), *(u32 *)(header->e_ident));
  ElfSectionData data = {.sections = new ElfSection[header->e_shnum], .count = header->e_shnum};
  const auto sec_names_offset_hdr =
    objfile->get_at_offset<Elf64_Shdr>(header->e_shoff + (header->e_shstrndx * header->e_shentsize));

  u64 min = UINTMAX_MAX;
  u64 max = 0;

  // good enough heuristic to determine mapped in ranges.
  for (auto i = 0; i < header->e_phnum; ++i) {
    auto phdr = objfile->get_at_offset<Elf64_Phdr>(header->e_phoff + header->e_phentsize * i);
    if (phdr->p_type == PT_LOAD) {
      min = std::min(phdr->p_vaddr, min);
      const auto end = u64{phdr->p_vaddr + phdr->p_memsz};
      const auto align_adjust = u64{phdr->p_align - (end % phdr->p_align)};
      max = std::max(end + align_adjust, max);
    }
  }

  objfile->unrelocated_address_bounds = AddressRange{.low = min, .high = max};
  auto sec_hdrs_offset = header->e_shoff;
  // parse sections
  for (auto i = 0; i < data.count; i++) {
    const auto sec_hdr = objfile->get_at_offset<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    data.sections[i].m_section_ptr = objfile->get_at_offset<u8>(sec_hdr->sh_offset);
    data.sections[i].m_section_size = sec_hdr->sh_size;
    data.sections[i].m_name =
      objfile->get_at_offset<const char>(sec_names_offset_hdr->sh_offset + sec_hdr->sh_name);
    data.sections[i].file_offset = sec_hdr->sh_offset;
    data.sections[i].address = sec_hdr->sh_addr;
  }
  // ObjectFile is the owner of `Elf`
  objfile->elf = new Elf{header, data, *objfile};
  objfile->elf->parse_min_symbols();
  objfile->unwinder = sym::parse_eh(objfile.get(), objfile->elf->get_section(".eh_frame"));
  if (const auto section = objfile->elf->get_section(".debug_frame"); section) {
    DBGLOG(core, ".debug_frame section found; parsing DWARF CFI section");
    sym::parse_dwarf_eh(objfile->elf, objfile->unwinder.get(), section, -1);
  }

  if (objfile->elf->has_dwarf()) {
    objfile->initial_dwarf_setup(Tracer::Instance->getConfig().dwarf_config());
  }

  return objfile;
}

SymbolFile::SymbolFile(TraceeController *tc, std::string obj_id, std::shared_ptr<ObjectFile> &&binary,
                       AddrPtr relocated_base) noexcept
    : binary_object(std::move(binary)), tc(tc), obj_id(std::move(obj_id)), baseAddress(relocated_base),
      pc_bounds(AddressRange::relocate(binary_object->unrelocated_address_bounds, relocated_base))
{
}

SymbolFile::shr_ptr
SymbolFile::Create(TraceeController *tc, std::shared_ptr<ObjectFile> binary, AddrPtr relocated_base) noexcept
{
  ASSERT(binary != nullptr, "SymbolFile was provided no backing ObjectFile");

  return std::make_shared<SymbolFile>(tc, fmt::format("{}:{}", tc->get_task_leader(), binary->path->c_str()),
                                      std::move(binary), relocated_base);
}

auto
SymbolFile::copy(TraceeController &tc, AddrPtr relocated_base) const noexcept -> std::shared_ptr<SymbolFile>
{
  return SymbolFile::Create(&tc, binary_object, relocated_base);
}

auto
SymbolFile::getCusFromPc(AddrPtr pc) noexcept -> std::vector<sym::dw::UnitData *>
{
  return objectFile()->get_cus_from_pc(pc - baseAddress->get());
}

auto
SymbolFile::symbolFileId() const noexcept -> std::string_view
{
  return obj_id;
}

inline auto
SymbolFile::objectFile() const noexcept -> ObjectFile *
{
  return binary_object.get();
}

auto
SymbolFile::contains(AddrPtr pc) const noexcept -> bool
{
  return pc_bounds->contains(pc);
}

auto
SymbolFile::unrelocate(AddrPtr pc) const noexcept -> AddrPtr
{
  ASSERT(pc > baseAddress, "PC={} is below base address {}.", pc, baseAddress);
  return pc - baseAddress;
}

auto
SymbolFile::registerResolver(std::shared_ptr<sym::Value> &value) noexcept -> void
{
  // TODO(simon): For now this "infrastructure" just hardcodes support for custom visualization of C-strings
  //   the idea, is that we later on should be able to extend this to plug in new resolvers & printers/visualizers.
  //   remember: we don't just lump everything into "pretty printer"; we have distinct ideas about how to resolve
  //   values and how to display them, which *is* the issue with GDB's pretty printers
  auto type = value->type()->resolve_alias();

  if (auto resolver = objectFile()->find_custom_resolver(*type); resolver != nullptr) {
    value->set_resolver(std::move(resolver));
    return;
  }
  auto layout_type = type->get_layout_type();

  const auto array_type = type->is_array_type();
  if (type->is_reference() && !array_type) {
    if (layout_type->is_char_type()) {
      DBGLOG(core, "[datviz]: setting cstring resolver for value");
      auto ptr = std::make_unique<sym::CStringResolver>(this, value, value->type());
      value->set_resolver(std::move(ptr));
    } else {
      DBGLOG(core, "[datviz]: setting pointer resolver for value");
      value->set_resolver(std::make_unique<sym::ReferenceResolver>(this, value, value->type()));
    }
    return;
  }

  // todo: again, this is hardcoded, which is counter to the whole idea here.
  if (array_type) {
    DBGLOG(core, "[datviz]: setting array resolver for value");
    auto layout_type = type->get_layout_type();
    auto ptr = std::make_unique<sym::ArrayResolver>(this, layout_type, type->array_size(), value->address());
    value->set_resolver(std::move(ptr));
    value = sym::Value::WithVisualizer<sym::ArrayVisualizer>(std::move(value));
    return;
  }
}

auto
SymbolFile::getVariables(TraceeController &tc, sym::Frame &frame,
                         sym::VariableSet set) noexcept -> std::vector<ui::dap::Variable>
{
  if (!frame.full_symbol_info().is_resolved()) {
    sym::dw::FunctionSymbolicationContext sym_ctx{*this->objectFile(), frame};
    sym_ctx.process_symbol_information();
  }

  switch (set) {
  case sym::VariableSet::Arguments: {
    return getVariablesImpl(sym::FrameVariableKind::Arguments, tc, frame);
  }
  case sym::VariableSet::Locals: {
    return getVariablesImpl(sym::FrameVariableKind::Locals, tc, frame);
  }
  case sym::VariableSet::Static:
  case sym::VariableSet::Global:
    TODO("Static or global variables request not yet supported.");
    break;
  }
  return {};
}
auto
SymbolFile::getSourceInfos(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>
{
  return binary_object->get_source_infos(pc - *baseAddress);
}

auto
SymbolFile::getSourceCodeFiles(AddrPtr pc) noexcept -> std::vector<sym::dw::RelocatedSourceCodeFile>
{
  return binary_object->relocated_get_source_code_files(baseAddress, pc);
}

auto
SymbolFile::resolve(const VariableContext &ctx, std::optional<u32> start,
                    std::optional<u32> count) noexcept -> std::vector<ui::dap::Variable>
{
  auto value = ctx.get_maybe_value();
  if (value == nullptr) {
    DBGLOG(core, "WARNING expected variable reference {} had no data associated with it.", ctx.id);
    return {};
  }
  auto type = value->type();
  if (!type->is_resolved()) {
    sym::dw::TypeSymbolicationContext ts_ctx{*objectFile(), *type};
    ts_ctx.resolve_type();
  }

  auto value_resolver = value->get_resolver();
  if (value_resolver != nullptr) {
    auto variables = value_resolver->resolve(*ctx.tc, start, count);
    std::vector<ui::dap::Variable> result{};

    for (auto &var : variables) {
      objectFile()->init_visualizer(var);
      registerResolver(var);
      const auto new_ref = var->type()->is_primitive() ? 0 : Tracer::Instance->clone_from_var_context(ctx);
      if (new_ref > 0) {
        ctx.t->cache_object(new_ref, var);
      }
      result.push_back(ui::dap::Variable{static_cast<int>(new_ref), var});
    }

    return result;
  } else {
    std::vector<ui::dap::Variable> result{};
    result.reserve(type->member_variables().size());

    for (auto &mem : type->member_variables()) {
      auto member_value = std::make_shared<sym::Value>(mem.name, const_cast<sym::Field &>(mem),
                                                       value->mem_contents_offset, value->take_memory_reference());
      objectFile()->init_visualizer(member_value);
      registerResolver(member_value);
      const auto new_ref =
        member_value->type()->is_primitive() ? 0 : Tracer::Instance->clone_from_var_context(ctx);
      if (new_ref > 0) {
        ctx.t->cache_object(new_ref, member_value);
      }
      result.push_back(ui::dap::Variable{static_cast<int>(new_ref), std::move(member_value)});
    }
    return result;
  }
}

auto
SymbolFile::low_pc() noexcept -> AddrPtr
{
  return baseAddress + objectFile()->unrelocated_address_bounds.low;
}

auto
SymbolFile::high_pc() noexcept -> AddrPtr
{
  return baseAddress + objectFile()->unrelocated_address_bounds.high;
}

auto
SymbolFile::getMinimalFnSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>
{
  return binary_object->get_min_fn_sym(name);
}

auto
SymbolFile::searchMinSymFnInfo(AddrPtr pc) noexcept -> const MinSymbol *
{
  return objectFile()->search_minsym_fn_info(pc - *baseAddress);
}

auto
SymbolFile::getMinimalSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>
{
  return binary_object->get_min_obj_sym(name);
}

auto
SymbolFile::getLineTable(u64 offset) noexcept -> sym::dw::LineTable
{
  auto &headers = *objectFile()->lnp_headers;
  auto header = std::find_if(headers.begin(), headers.end(),
                             [o = offset](const sym::dw::LNPHeader &header) { return header.sec_offset == o; });
  ASSERT(header != std::end(headers), "Failed to find LNP Header with offset 0x{:x}", offset);

  auto kvp = std::find_if(objectFile()->parsed_ltes->begin(), objectFile()->parsed_ltes->end(),
                          [offset](const auto &kvp) { return kvp.first == offset; });
  if (kvp == std::end(*objectFile()->parsed_ltes)) {
    PANIC(fmt::format("Failed to find parsed LineTable Entries for offset 0x{:x}", offset));
  }
  if (kvp->second.table.empty()) {
    sym::dw::compute_line_number_program(kvp->second, objectFile()->elf, &*header);
  }
  return sym::dw::LineTable{&(*header), &kvp->second, baseAddress};
}

auto
SymbolFile::path() const noexcept -> Path
{
  return binary_object->path;
}

auto
SymbolFile::supervisor() noexcept -> TraceeController *
{
  return tc;
}

auto
SymbolFile::lookup_by_spec(const FunctionBreakpointSpec &spec) noexcept -> std::vector<BreakpointLookup>
{

  std::vector<MinSymbol> matching_symbols;
  std::vector<BreakpointLookup> result{};

  auto obj = objectFile();
  std::vector<std::string> search_for{};
  if (spec.is_regex) {
    const auto start = std::chrono::high_resolution_clock::now();
    search_for = obj->regex_search(spec.name);
    const auto elapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
        .count();
    DBGLOG(core, "regex searched {} in {}us", obj->path->c_str(), elapsed);
  } else {
    search_for = {spec.name};
  }

  for (const auto &n : search_for) {
    auto ni = obj->name_index();
    ni->for_each_fn(n, [&](const sym::dw::DieNameReference &ref) {
      auto die_ref = ref.cu->get_cu_die_ref(ref.die_index);
      auto low_pc = die_ref.read_attribute(Attribute::DW_AT_low_pc);
      if (low_pc) {
        const auto addr = low_pc->address();
        matching_symbols.emplace_back(n, addr, 0);
        DBGLOG(core, "[{}][cu=0x{:x}, die=0x{:x}] found fn {} at low_pc of {}", obj->path->c_str(),
               die_ref.GetUnitData()->section_offset(), die_ref.GetDie()->section_offset, n, addr);
      }
    });
  }

  Set<AddrPtr> bps_set{};
  for (const auto &sym : matching_symbols) {
    const auto unrelocated = sym.address;
    const auto adjusted_address = sym.address + baseAddress;
    if (!bps_set.contains(unrelocated)) {
      auto srcs = getSourceCodeFiles(unrelocated);
      for (auto src : srcs) {
        if (src.address_bounds().contains(adjusted_address)) {
          if (auto lte = src.find_lte_by_pc(unrelocated).transform([](auto v) { return v.get(); });
              lte && !bps_set.contains(unrelocated)) {
            result.emplace_back(adjusted_address, LocationSourceInfo{src.path(), lte->line, u32{lte->column}});
            bps_set.insert(sym.address);
          }
        }
      }
    }
  }

  for (const auto &n : search_for) {
    if (auto s = obj->get_min_fn_sym(n).transform([&](const auto &sym) { return sym.address + baseAddress; });
        s.has_value() && !bps_set.contains(s.value())) {
      result.emplace_back(s.value(), std::nullopt);
      bps_set.insert(s.value());
    }
  }

  return result;
}

auto
SymbolFile::getVariablesImpl(sym::FrameVariableKind variables_kind, TraceeController &tc,
                             sym::Frame &frame) noexcept -> std::vector<ui::dap::Variable>
{
  std::vector<ui::dap::Variable> result{};
  switch (variables_kind) {
  case sym::FrameVariableKind::Arguments:
    result.reserve(frame.frame_args_count());
    break;
  case sym::FrameVariableKind::Locals:
    result.reserve(frame.frame_locals_count());
    break;
  }

  for (auto &symbol : frame.block_symbol_iterator(variables_kind)) {
    const auto ref = symbol.type->is_primitive() ? 0 : Tracer::Instance->new_key();
    if (ref == 0 && !symbol.type->is_resolved()) {
      sym::dw::TypeSymbolicationContext ts_ctx{*this->objectFile(), symbol.type};
      ts_ctx.resolve_type();
    }

    auto value_object = sym::MemoryContentsObject::create_frame_variable(tc, frame.task, NonNull(frame),
                                                                         const_cast<sym::Symbol &>(symbol), true);
    objectFile()->init_visualizer(value_object);
    registerResolver(value_object);

    if (ref > 0) {
      Tracer::Instance->set_var_context({&tc, frame.task->ptr, frame.get_symbol_file(),
                                         static_cast<u32>(frame.id()), static_cast<u16>(ref),
                                         ContextType::Variable});
      frame.task.mut()->cache_object(ref, value_object);
    }
    result.push_back(ui::dap::Variable{static_cast<int>(ref), std::move(value_object)});
  }
  return result;
}