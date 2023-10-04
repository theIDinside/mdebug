#include "objfile.h"
#include "elf_symbols.h"
#include "so_loading.h"
#include "symbol/dwarf2/unit.h"
#include "type.h"
#include <algorithm>

// SYMBOLS namespace
namespace sym {

ObjectFile::ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), size(size), loaded_binary(loaded_binary), minimal_fn_symbols{}, minimal_obj_symbols{},
      types(), line_tables(), line_table_headers(), unwinder(nullptr), address_bounds(), m_full_cu(),
      m_partial_units(), parsed_elf(nullptr), unit_data_lock(), m_name_index()
{
  ASSERT(size > 0, "Loaded Object File is invalid");
}

ObjectFile::~ObjectFile() noexcept
{
  delete elf();
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
  return elf()->get_section(".text")->address;
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
  const auto path = interpreter_path(elf()->get_section(".interp"));
  return path;
}

dw::LineHeader *
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

Elf *
ObjectFile::get_elf() noexcept
{
  return parsed_elf;
}

std::vector<dw2::DwarfUnitData *> &
ObjectFile::get_cus() noexcept
{
  if (!dwarf_units.empty())
    return dwarf_units;

  auto new_headers = sym::dw2::read_cu_headers(this);
  // create TaskGroup
  utils::TaskGroup tg("dwarf unit data");
  auto work = sym::dw2::DwarfUnitDataTask::create_work(this, new_headers);
  for (auto w : work) {
    tg.add_task(w);
  }
  tg.schedule_tasks().wait();
  return dwarf_units;
}

void
ObjectFile::set_unit_data(const std::vector<dw2::DwarfUnitData *> &unit_data) noexcept
{
  DLOG("mdb", "Caching {} unit datas", unit_data.size());
  std::lock_guard lock(unit_data_lock);
  auto first_id = unit_data.front()->get_id();
  const auto it = std::lower_bound(dwarf_units.begin(), dwarf_units.end(), first_id,
                                   [](const dw2::DwarfUnitData *ptr, u64 id) { return ptr->get_id() < id; });
  dwarf_units.insert(it, unit_data.begin(), unit_data.end());
}

dw2::DwarfUnitData *
ObjectFile::get_containing_cu(dw2::DwarfId sec_offset) noexcept
{
  const auto it = std::lower_bound(dwarf_units.begin(), dwarf_units.end(), sec_offset.get_id(),
                                   [](const dw2::DwarfUnitData *cu, u64 id) { return cu->get_id() < id; });
  if (it == std::end(dwarf_units)) {
    DLOG("mdb", "did not find CU containing 0x{:x}", sec_offset.get_id());
    return nullptr;
  }
  return *it;
}

sym::dw2::NameIndex &
ObjectFile::get_name_index() noexcept
{
  return m_name_index;
}
}; // namespace sym