#include "objfile.h"
#include "../so_loading.h"
#include "./dwarf/name_index.h"
#include "dwarf.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "supervisor.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/dwarf_defs.h"
#include "symbolication/value_visualizer.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tasks/lnp.h"
#include "type.h"
#include "utils/enumerator.h"
#include "utils/worker_task.h"
#include "value.h"
#include <symbolication/dwarf/typeread.h>
#include <utils/scoped_fd.h>

ObjectFile::ObjectFile(std::string objfile_id, Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), objfile_id(std::move(objfile_id)), size(size), loaded_binary(loaded_binary),
      types(std::make_unique<TypeStorage>(*this)), minimal_fn_symbols{}, min_fn_symbols_sorted(),
      minimal_obj_symbols{}, unit_data_write_lock(), dwarf_units(),
      name_to_die_index(std::make_unique<sym::dw::ObjectFileNameIndex>()), parsed_lte_write_lock(), line_table(),
      lnp_headers(nullptr),
      parsed_ltes(std::make_shared<std::unordered_map<u64, sym::dw::ParsedLineTableEntries>>()), cu_write_lock(),
      comp_units(), addr_cu_map(), valobj_cache{}
{
  ASSERT(size > 0, "Loaded Object File is invalid");
}

ObjectFile::~ObjectFile() noexcept
{
  delete parsed_elf;
  munmap((void *)loaded_binary, size);
}

u64
ObjectFile::get_offset(u8 *ptr) const noexcept
{
  ASSERT(ptr > loaded_binary, "Attempted to take address before {:p} with {:p}", (void *)loaded_binary,
         (void *)ptr);
  ASSERT((u64)(ptr - loaded_binary) < size, "Pointer is outside of bounds of 0x{:x} .. {:x}",
         (std::uintptr_t)loaded_binary, (std::uintptr_t)(loaded_binary + size))
  return ptr - loaded_binary;
}

AddrPtr
ObjectFile::text_section_offset() const noexcept
{
  return parsed_elf->get_section(".text")->address;
}

std::optional<MinSymbol>
ObjectFile::get_min_fn_sym(std::string_view name) noexcept
{
  if (minimal_fn_symbols.contains(name)) {
    auto &index = minimal_fn_symbols[name];
    return min_fn_symbols_sorted[index];
  } else {
    return std::nullopt;
  }
}

const MinSymbol *
ObjectFile::search_minsym_fn_info(AddrPtr pc) noexcept
{
  auto it = std::lower_bound(min_fn_symbols_sorted.begin(), min_fn_symbols_sorted.end(), pc,
                             [](auto &sym, AddrPtr addr) { return sym.start_pc() < addr; });
  if (it == std::end(min_fn_symbols_sorted))
    return nullptr;

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

bool
ObjectFile::found_min_syms() const noexcept
{
  return has_elf_symbols;
}

void
ObjectFile::set_unit_data(const std::vector<sym::dw::UnitData *> &unit_data) noexcept
{
  ASSERT(!unit_data.empty(), "Expected unit data to be non-empty");
  DLOG("mdb", "Caching {} unit datas", unit_data.size());
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
  if (it != std::end(dwarf_units))
    return *it;
  else
    return nullptr;
}

std::optional<sym::dw::DieReference>
ObjectFile::get_die_reference(u64 offset) noexcept
{
  auto cu = get_cu_from_offset(offset);
  if (cu == nullptr)
    return {};
  auto die = cu->get_die(offset);
  if (die == nullptr)
    return {};

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
    if (header.sec_offset == offset)
      return &header;
  }
  TODO_FMT("handle requests of line table headers that aren't yet parsed (offset={})", offset);
}

sym::dw::LineTable
ObjectFile::get_linetable(u64 offset) noexcept
{
  auto &headers = *lnp_headers;
  auto header = std::find_if(headers.begin(), headers.end(),
                             [o = offset](const sym::dw::LNPHeader &header) { return header.sec_offset == o; });
  ASSERT(header != std::end(headers), "Failed to find LNP Header with offset 0x{:x}", offset);
  auto kvp = std::find_if(parsed_ltes->begin(), parsed_ltes->end(),
                          [offset](const auto &kvp) { return kvp.first == offset; });
  if (kvp == std::end(*parsed_ltes)) {
    PANIC(fmt::format("Failed to find parsed LineTable Entries for offset 0x{:x}", offset));
  }
  if (kvp->second.table.empty()) {
    sym::dw::compute_line_number_program(kvp->second, parsed_elf, &*header);
  }
  return sym::dw::LineTable{&(*header), &kvp->second, parsed_elf->relocate_addr(nullptr)};
}

void
ObjectFile::read_lnp_headers() noexcept
{
  lnp_headers = sym::dw::read_lnp_headers(parsed_elf);

  std::string path_buf{};
  path_buf.reserve(1024);
  for (auto &hdr : *lnp_headers) {
    for (const auto &f : hdr.file_names) {
      path_buf.clear();
      const auto index = hdr.version == DwarfVersion::D4 ? f.dir_index - 1 : f.dir_index;
      // this should be safe, because the string_views (which we call .data() on) are originally null-terminated
      // and we have not made copies.
      fmt::format_to(std::back_inserter(path_buf), "{}/{}", hdr.directories[index].path, f.file_name);
      const auto canonical = std::filesystem::path{path_buf}.lexically_normal();
      auto it = lnp_source_code_files.find(canonical);
      if (it != std::end(lnp_source_code_files)) {
        it->second->add_header(&hdr);
      } else {
        std::vector<sym::dw::LNPHeader *> src_headers{};
        src_headers.push_back(&hdr);
        lnp_source_code_files.emplace(
            canonical, std::make_shared<sym::dw::SourceCodeFile>(parsed_elf, canonical, std::move(src_headers)));
      }
    }
  }
  init_lnp_storage(*lnp_headers);
}

// No synchronization needed, parsed 1, in 1 thread
std::span<sym::dw::LNPHeader>
ObjectFile::get_lnp_headers() noexcept
{
  if (lnp_headers)
    return std::span{*lnp_headers};
  else {
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
ObjectFile::add_initialized_cus(std::span<sym::SourceFileSymbolInfo> new_cus) noexcept
{
  // TODO(simon): We do stupid sorting. implement something better optimized
  std::lock_guard lock(cu_write_lock);
  comp_units.insert(comp_units.end(), std::make_move_iterator(new_cus.begin()),
                    std::make_move_iterator(new_cus.end()));
  std::sort(comp_units.begin(), comp_units.end(), sym::SourceFileSymbolInfo::Sorter());

  DBG({
    if (!std::is_sorted(comp_units.begin(), comp_units.end(), sym::SourceFileSymbolInfo::Sorter())) {
      for (const auto &cu : comp_units) {
        DLOG("mdb", "[cu dwarf offset=0x{:x}]: start_pc = {}, end_pc={}", cu.get_dwarf_unit()->section_offset(),
             cu.start_pc(), cu.end_pc());
      }
      PANIC("Dumped CU contents");
    }
  })
  addr_cu_map.add_cus(new_cus);
}

std::vector<sym::SourceFileSymbolInfo> &
ObjectFile::source_units() noexcept
{
  return comp_units;
}

SharedPtr<sym::dw::SourceCodeFile>
ObjectFile::get_source_file(const std::filesystem::path &fullpath) noexcept
{
  auto it = lnp_source_code_files.find(fullpath);
  if (it != std::end(lnp_source_code_files)) {
    return it->second;
  }
  return nullptr;
}

std::vector<sym::dw::UnitData *>
ObjectFile::get_cus_from_pc(AddrPtr pc) noexcept
{
  return addr_cu_map.find_by_pc(pc - parsed_elf->relocate_addr(nullptr));
}

// TODO(simon): Implement something more efficient. For now, we do the absolute worst thing, but this problem is
// uninteresting for now and not really important, as it can be fixed at any point in time.
std::vector<sym::SourceFileSymbolInfo *>
ObjectFile::get_source_infos(AddrPtr pc) noexcept
{
  std::vector<sym::SourceFileSymbolInfo *> result;
  auto unit_datas = addr_cu_map.find_by_pc(pc - parsed_elf->relocate_addr(nullptr));
  for (auto &src : source_units()) {
    for (auto *unit : unit_datas) {
      if (src.get_dwarf_unit() == unit) {
        result.push_back(&src);
      }
    }
  }
  return result;
}

std::vector<sym::dw::SourceCodeFile *>
ObjectFile::get_source_code_files(AddrPtr pc) noexcept
{
  std::vector<sym::dw::SourceCodeFile *> result;
  auto cus = get_source_infos(pc);
  const auto is_unique = [&](auto ptr) noexcept {
    return std::none_of(result.begin(), result.end(), [ptr](auto cmp) { return ptr == cmp; });
  };
  for (auto cu : cus) {
    for (auto src : cu->sources()) {
      if (src->address_bounds().contains(pc) && is_unique(src.get())) {
        result.push_back(src.get());
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
  DLOG("mdb", "Name Indexing block done");
}

void
ObjectFile::add_elf_symbols(std::vector<MinSymbol> &&fn_symbols,
                            std::unordered_map<std::string_view, MinSymbol> &&obj_symbols) noexcept
{
  min_fn_symbols_sorted = std::move(fn_symbols);
  minimal_obj_symbols = std::move(obj_symbols);
  init_minsym_name_lookup();
  has_elf_symbols = true;
}

void
ObjectFile::init_minsym_name_lookup() noexcept
{
  for (const auto &[index, sym] : utils::EnumerateView(min_fn_symbols_sorted)) {
    minimal_fn_symbols[sym.name] = Index{static_cast<u32>(index)};
  }
}

std::vector<ui::dap::Variable>
ObjectFile::resolve(TraceeController &tc, int ref, std::optional<u32> start, std::optional<u32> count) noexcept
{
  if (!valobj_cache.contains(ref)) {
    DLOG("mdb", "WARNING expected variable reference {} had no data associated with it.", ref);
    return {};
  }
  auto &value = valobj_cache[ref];
  auto type = value->type();
  if (!type->is_resolved()) {
    sym::dw::TypeSymbolicationContext ts_ctx{*this, *type};
    ts_ctx.resolve_type();
  }

  auto value_resolver = value->get_resolver();
  if (value_resolver != nullptr) {
    auto variables = value_resolver->resolve(tc, start, count);
    std::vector<ui::dap::Variable> result{};

    for (auto &var : variables) {
      init_visualizer(var);
      register_resolver(var);
      const auto new_ref = var->type()->is_primitive() ? 0 : tc.new_var_id(ref);
      if (new_ref > 0)
        cache_value(new_ref, var);
      result.push_back(ui::dap::Variable{new_ref, var});
    }

    return result;
  } else {
    std::vector<ui::dap::Variable> result{};
    result.reserve(type->member_variables().size());

    for (auto &mem : type->member_variables()) {
      auto member_value = std::make_shared<sym::Value>(mem.name, const_cast<sym::Field &>(mem),
                                                       value->mem_contents_offset, value->take_memory_reference());
      init_visualizer(member_value);
      register_resolver(member_value);
      const auto new_ref = member_value->type()->is_primitive() ? 0 : tc.new_var_id(ref);
      if (new_ref > 0)
        cache_value(new_ref, member_value);
      result.push_back(ui::dap::Variable{new_ref, std::move(member_value)});
    }
    return result;
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
  if (value->has_visualizer())
    return;

  auto &type = *value->type();
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

void
ObjectFile::register_resolver(std::shared_ptr<sym::Value> &value) noexcept
{
  // TODO(simon): For now this "infrastructure" just hardcodes support for custom visualization of C-strings
  //   the idea, is that we later on should be able to extend this to plug in new resolvers & printers/visualizers.
  //   remember: we don't just lump everything into "pretty printer"; we have distinct ideas about how to resolve
  //   values and how to display them, which *is* the issue with GDB's pretty printers
  auto type = value->type();

  if (auto resolver = find_custom_resolver(*type); resolver != nullptr) {
    value->set_resolver(std::move(resolver));
    return;
  }
  auto layout_type = type->get_layout_type();
  if (type->is_reference() && layout_type->is_char_type()) {
    DLOG("mdb", "setting cstring resolver for value");
    auto ptr = std::make_unique<sym::CStringResolver>(this, value, value->type());
    value->set_resolver(std::move(ptr));
    return;
  }

  // todo: again, this is hardcoded, which is counter to the whole idea here.
  if (type->is_array_type()) {
    DLOG("mdb", "setting array resolver for value");
    auto layout_type = type->get_layout_type();
    auto ptr = std::make_unique<sym::ArrayResolver>(this, layout_type, type->array_size(), value->address());
    value->set_resolver(std::move(ptr));
    value = sym::Value::WithVisualizer<sym::ArrayVisualizer>(std::move(value));
  }
}

void
ObjectFile::cache_value(VariablesReference ref, sym::Value::ShrPtr value) noexcept
{
  ASSERT(!valobj_cache.contains(ref), "Value object cache already contains value with reference {}", ref);
  valobj_cache.emplace(ref, std::move(value));
}

void
ObjectFile::invalidate_variable_references() noexcept
{
  valobj_cache.clear();
}

std::vector<ui::dap::Variable>
ObjectFile::get_variables_impl(sym::FrameVariableKind variables_kind, TraceeController &tc,
                               sym::Frame &frame) noexcept
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
    const auto ref = symbol.type->is_primitive() ? 0 : tc.new_var_id(frame.id());
    if (ref == 0 && !symbol.type->is_resolved()) {
      sym::dw::TypeSymbolicationContext ts_ctx{*this, symbol.type};
      ts_ctx.resolve_type();
    }
    auto value_object = sym::MemoryContentsObject::create_frame_variable(tc, frame.task, NonNull(frame),
                                                                         const_cast<sym::Symbol &>(symbol), true);
    init_visualizer(value_object);
    register_resolver(value_object);

    if (ref > 0)
      cache_value(ref, value_object);
    result.push_back(ui::dap::Variable{ref, std::move(value_object)});
  }
  return result;
}

std::vector<ui::dap::Variable>
ObjectFile::get_variables(TraceeController &tc, sym::Frame &frame, sym::VariableSet set) noexcept
{
  if (!frame.full_symbol_info().is_resolved()) {
    sym::dw::FunctionSymbolicationContext sym_ctx{*this, frame};
    sym_ctx.process_symbol_information();
  }

  switch (set) {
  case sym::VariableSet::Arguments: {
    return get_variables_impl(sym::FrameVariableKind::Arguments, tc, frame);
  }
  case sym::VariableSet::Locals: {
    return get_variables_impl(sym::FrameVariableKind::Locals, tc, frame);
  }
  case sym::VariableSet::Static:
  case sym::VariableSet::Global:
    TODO("Static or global variables request not yet supported.");
    break;
  }
  return {};
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
      new ObjectFile{fmt::format("{}:{}", tc.task_leader, path.c_str()), path, fd.file_size(), addr};

  return objfile;
}