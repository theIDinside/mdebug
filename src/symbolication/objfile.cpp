#include "objfile.h"
#include "../so_loading.h"
#include "./dwarf/name_index.h"
#include "cu.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "elf_symbols.h"
#include "source_file.h"
#include "type.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <optional>

ObjectFile::ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), size(size), loaded_binary(loaded_binary), minimal_fn_symbols{}, minimal_obj_symbols{},
      types(), line_tables(), line_table_headers(), unwinder(nullptr), address_bounds(), m_full_cu(),
      m_partial_units(), unit_data_write_lock(), dwarf_units(),
      name_to_die_index(std::make_unique<sym::dw::ObjectFileNameIndex>()), parsed_lte_write_lock(), line_table(),
      lnp_headers(nullptr),
      parsed_ltes(std::make_shared<std::unordered_map<u64, sym::dw::ParsedLineTableEntries>>()), cu_write_lock(),
      comp_units()
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

LineHeader *
ObjectFile::line_table_header(u64 offset) noexcept
{
  for (auto &lth : line_table_headers) {
    if (lth.sec_offset == offset)
      return &lth;
  }
  TODO_FMT("handle requests of line table headers that aren't yet parsed (offset={})", offset);
}

SearchResult<CompilationUnitFile>
ObjectFile::get_cu_iterable(AddrPtr addr) const noexcept
{
  if (const auto it = find(m_full_cu, [addr](const auto &f) { return f.may_contain(addr); });
      it != std::cend(m_full_cu)) {
    return SearchResult<CompilationUnitFile>{.ptr = it.base(),
                                             .index = static_cast<u32>(std::distance(m_full_cu.cbegin(), it)),
                                             .cap = static_cast<u32>(m_full_cu.size())};
  }
  return {nullptr, 0, 0};
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
  auto header = std::ranges::find_if(
      headers, [o = offset](const sym::dw::LNPHeader &header) { return header.sec_offset == o; });
  ASSERT(header != std::end(headers), "Failed to find LNP Header with offset 0x{:x}", offset);
  auto kvp = std::find_if(parsed_ltes->begin(), parsed_ltes->end(),
                          [offset](const auto &kvp) { return kvp.first == offset; });
  ASSERT(kvp != std::end(*parsed_ltes), "Failed to find parsed LineTable Entries for offset 0x{:x}", offset);
  return sym::dw::LineTable{header.base(), &kvp->second, parsed_elf->relocate_addr(nullptr)};
}

void
ObjectFile::read_lnp_headers() noexcept
{
  lnp_headers = sym::dw::read_lnp_headers(parsed_elf);
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
  ASSERT(headers.size() == parsed_ltes.size(), "headers != parsed_lte count!");
  auto h = headers.begin();
  auto p = std::make_move_iterator(parsed_ltes.begin());
  auto &stored = *this->parsed_ltes;
  for (; h != std::end(headers); h++, p++) {
    stored.emplace(h->sec_offset, std::move(*p));
  }
}

void
ObjectFile::add_initialized_cus(std::span<sym::CompilationUnit> new_cus) noexcept
{
  DLOG("mdb", "Adding {} compilation units", new_cus.size());
  std::lock_guard lock(cu_write_lock);
  auto insert_it =
      std::find_if(comp_units.begin(), comp_units.end(),
                   [pc = new_cus.begin()->low_pc()](const sym::CompilationUnit &cu) { return pc < cu.low_pc(); });

  comp_units.insert(insert_it, std::make_move_iterator(new_cus.begin()), std::make_move_iterator(new_cus.end()));
  ASSERT(std::is_sorted(comp_units.begin(), comp_units.end(), sym::CompilationUnit::SortByBounds{}),
         "Compilation units is not sorted");
}

std::vector<sym::CompilationUnit> &
ObjectFile::source_units() noexcept
{
  return comp_units;
}

ObjectFile *
mmap_objectfile(const Path &path) noexcept
{
  if (!fs::exists(path)) {
    return nullptr;
  }

  auto fd = ScopedFd::open_read_only(path);
  const auto addr = mmap_file<u8>(fd, fd.file_size(), true);
  auto objfile = new ObjectFile{path, fd.file_size(), addr};
  return objfile;
}