#include "type.h"
#include "block.h"
#include "dwarf.h"
#include "elf.h"
#include "lnp.h"
#include <algorithm>
#include <emmintrin.h>
#include <filesystem>

CompilationUnitFile::CompilationUnitFile(DebugInfoEntry *cu, const Elf *elf) noexcept
    : m_addr_ranges(), m_name(), pc_boundaries(), line_header(nullptr), fns(), cu_die(cu), elf(elf)
{
}

CompilationUnitFile::CompilationUnitFile(CompilationUnitFile &&o) noexcept
    : m_addr_ranges(std::move(o.m_addr_ranges)), m_name(o.m_name), pc_boundaries(o.pc_boundaries),
      line_header(o.line_header), fns(std::move(o.fns)), cu_die(o.cu_die)
{
}

CompilationUnitFile &
CompilationUnitFile::operator=(CompilationUnitFile &&o) noexcept
{
  if (this == &o)
    return *this;
  m_addr_ranges = std::move(o.m_addr_ranges);
  m_name = o.m_name;
  pc_boundaries = o.pc_boundaries;
  line_header = o.line_header;
  fns = std::move(o.fns);
  cu_die = o.cu_die;
  return *this;
}

Path
CompilationUnitFile::dir() const noexcept
{
  Path p{m_name};
  return p.root_directory();
}

Path
CompilationUnitFile::source_filename() const noexcept
{
  Path p{m_name};
  return p.filename();
}

Path
CompilationUnitFile::fullpath() const noexcept
{
  return m_name;
}

std::string_view
CompilationUnitFile::name() const noexcept
{
  return m_name;
}

AddrPtr
CompilationUnitFile::low_pc() const noexcept
{
  return pc_boundaries.low;
}

AddrPtr
CompilationUnitFile::high_pc() const noexcept
{
  return pc_boundaries.high;
}

void
CompilationUnitFile::set_name(std::string_view name) noexcept
{
  m_name = name;
}

void
CompilationUnitFile::add_addr_rng(const u64 *start) noexcept
{
  m_addr_ranges.push_back(AddressRange{});
  _mm_storeu_si128((__m128i *)&m_addr_ranges.back(), _mm_loadu_si128((__m128i *)start));
}

void
CompilationUnitFile::add_addr_rng(AddrPtr start, AddrPtr end) noexcept
{
  m_addr_ranges.push_back(AddressRange{start, end});
}

bool
CompilationUnitFile::last_added_addr_valid() const noexcept
{
  return m_addr_ranges.back().is_valid();
}

void
CompilationUnitFile::set_linetable(const LineHeader *header) noexcept
{
  DLOG("dwarf", "[lnp]: table=0x{:x}", header->sec_offset);
  line_header = header;
}

bool
CompilationUnitFile::known_addresses() const noexcept
{
  return !m_addr_ranges.empty() || (line_header && line_header->has_entries());
}

void
CompilationUnitFile::set_boundaries() noexcept
{
  if (!m_addr_ranges.empty()) {
    pc_boundaries = AddressRange{.low = m_addr_ranges.front().low, .high = m_addr_ranges.back().high};
  } else if (line_header && line_header->line_table) {
    pc_boundaries =
        AddressRange{.low = line_header->line_table->front().pc, .high = line_header->line_table->back().pc + 1};
  } else
    pc_boundaries = AddressRange{nullptr, nullptr};

  if (pc_boundaries.low > pc_boundaries.high) {
    DLOG("mdb", "faulty pc boundaries");
    for (const auto &lte : *(line_header->line_table)) {
      DLOG("mdb", "[LINE TABLE DUMP]: {}", lte);
    }
  }
  ASSERT(pc_boundaries.low <= pc_boundaries.high, "low must be <= high: {} <= {} ({})", pc_boundaries.low,
         pc_boundaries.high, this->m_name);
}

const LineTable &
CompilationUnitFile::line_table() const noexcept
{
  return *line_header->line_table;
}

const AddrRanges &
CompilationUnitFile::address_ranges() const noexcept
{
  return m_addr_ranges;
}

AddressRange
CompilationUnitFile::low_high_pc() const noexcept
{
  return pc_boundaries;
}

void
CompilationUnitFile::add_function(FunctionSymbol sym) noexcept
{
  using FnSym = FunctionSymbol;
  // N.B. if I got this right, this might cause problems with inlined functions. Though I'm not sure.
  auto it_pos = std::lower_bound(fns.begin(), fns.end(), sym.start,
                                 [](FnSym &fn, AddrPtr start) { return fn.start > start; });
  fns.insert(it_pos, sym);
}

const FunctionSymbol *
CompilationUnitFile::find_subprogram(AddrPtr addr) const noexcept
{
  const auto sym =
      std::find_if(fns.cbegin(), fns.cend(), [addr](auto &sym) { return sym.start <= addr && sym.end >= addr; });

  if (sym != std::end(fns)) {
    ASSERT(sym->start.get() <= addr.get() && addr.get() < sym->end.get(),
           "Found unexpectedly the wrong FunctionSymbol when searching for {}. Sym '{}' [{}..{}]", addr, sym->name,
           sym->start, sym->end);
    DLOG("mdb", "found {} from {}", sym->name, addr);
    return sym.base();
  } else {
    return nullptr;
  }
}

LineTableEntryRange
CompilationUnitFile::get_range(AddrPtr addr) const noexcept
{
  const auto &m_ltes = line_table();
  const auto lte_it = std::lower_bound(m_ltes.cbegin(), m_ltes.cend(), addr,
                                       [](const LineTableEntry &l, AddrPtr addr) { return l.pc <= addr; });
  if (lte_it == std::cend(m_ltes))
    return {nullptr, nullptr};
  if (lte_it + 1 == std::end(m_ltes))
    return {nullptr, nullptr};
  if ((lte_it + 1)->pc < addr)
    return {nullptr, nullptr};
  return {(lte_it - 1).base(), lte_it.base()};
}

LineTableEntryRange
CompilationUnitFile::get_range_of_pc(AddrPtr addr) const noexcept
{
  const auto &m_ltes = line_table();
  auto it = find(m_ltes, [addr](auto &lte) { return lte.pc > addr; });
  if (it == std::end(m_ltes) || it == std::begin(m_ltes))
    return {nullptr, nullptr};
  if ((it - 1)->pc > addr)
    return {nullptr, nullptr};
  return {(it - 1).base(), it.base()};
}

LineTableEntryRange
CompilationUnitFile::get_range(AddrPtr start, AddrPtr end) const noexcept
{
  TODO(fmt::format("CompilationUnitFile::get_range(TPtr<void> start = {}, TPtr<void> end = {})", start, end));
}

std::string_view
CompilationUnitFile::file(u32 index) const noexcept
{
  ASSERT(index < line_header->file_names.size(), "No file in this CU with that index");
  return line_header->file_names[index].file_name;
}

std::string_view
CompilationUnitFile::path_of_file(u32 index) const noexcept
{
  ASSERT(index < line_header->file_names.size(), "No file in this CU with that index");
  return line_header->directories[line_header->file_names[index].dir_index].path;
}

Path
CompilationUnitFile::file_path(u32 index) const noexcept
{
  ASSERT(index < line_header->file_names.size(), "No file in this CU with that index");
  auto &fentry = line_header->file_names[index];
  Path p = line_header->directories[fentry.dir_index].path;
  return p / fentry.file_name;
}