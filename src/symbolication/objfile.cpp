#include "objfile.h"
#include "../so_loading.h"
#include "./dwarf/name_index.h"
#include "symbolication/dwarf/lnp.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tasks/lnp.h"
#include "type.h"
#include "utils/worker_task.h"
#include <optional>
#include <utils/scoped_fd.h>

ObjectFile::ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), size(size), loaded_binary(loaded_binary), minimal_fn_symbols{}, minimal_obj_symbols{},
      types(), address_bounds(), unit_data_write_lock(), dwarf_units(),
      name_to_die_index(std::make_unique<sym::dw::ObjectFileNameIndex>()), parsed_lte_write_lock(), line_table(),
      lnp_headers(nullptr),
      parsed_ltes(std::make_shared<std::unordered_map<u64, sym::dw::ParsedLineTableEntries>>()), cu_write_lock(),
      comp_units(), addr_cu_map()
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
    return minimal_fn_symbols[name];
  } else {
    return std::nullopt;
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

Path
ObjectFile::interpreter() const noexcept
{
  const auto path = interpreter_path(parsed_elf, parsed_elf->get_section(".interp"));
  return path;
}

bool
ObjectFile::found_min_syms() const noexcept
{
  return min_syms;
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
    for (const auto &kvp : *parsed_ltes) {
      DLOG("mdb", "LTE: 0x{:x}", kvp.first);
    }
    ASSERT(false, "Failed to find parsed LineTable Entries for offset 0x{:x}", offset);
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
                            std::vector<sym::dw::ParsedLineTableEntries> &&parsed_ltes)
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

  if (!std::is_sorted(comp_units.begin(), comp_units.end(), sym::SourceFileSymbolInfo::Sorter())) {
    for (const auto &cu : comp_units) {
      DLOG("mdb", "[cu dwarf offset=0x{:x}]: start_pc = {}, end_pc={}", cu.get_dwarf_unit()->section_offset(),
           cu.start_pc(), cu.end_pc());
    }
    ASSERT(false, "Dumped CU contents");
  }
  addr_cu_map.add_cus(new_cus);
}

std::vector<sym::SourceFileSymbolInfo> &
ObjectFile::source_units() noexcept
{
  return comp_units;
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
        src.get_linetable();
        result.push_back(&src);
      }
    }
  }
  return result;
}

void
ObjectFile::initial_dwarf_setup(const sys::DwarfParseConfiguration &config) noexcept
{
  // First block of tasks need to finish before continuing with anything else.
  {
    utils::TaskGroup tg("Compilation Unit Data");
    auto work = sym::dw::UnitDataTask::create_jobs_for(this);
    tg.add_tasks(std::span{work});
    tg.schedule_work().wait();
    read_lnp_headers();
  }

  std::optional<std::future<void>> lnp_promise;
  if (config.eager_lnp_parse) {
    utils::TaskGroup tg("Line number programs");
    auto work = sym::dw::LineNumberProgramTask::create_jobs_for(this);
    tg.add_tasks(std::span{work});
    lnp_promise = tg.schedule_work();
  }

  {
    utils::TaskGroup tg("Name Indexing");
    auto work = sym::dw::IndexingTask::create_jobs_for(this);
    tg.add_tasks(std::span{work});
    tg.schedule_work().wait();
    if (lnp_promise) {
      lnp_promise->wait();
    }
  }
}

ObjectFile *
mmap_objectfile(const Path &path) noexcept
{
  if (!fs::exists(path)) {
    return nullptr;
  }

  auto fd = utils::ScopedFd::open_read_only(path);
  const auto addr = fd.mmap_file<u8>({}, true);
  auto objfile = new ObjectFile{path, fd.file_size(), addr};
  return objfile;
}