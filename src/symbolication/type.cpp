#include "type.h"
#include "block.h"
#include "dwarf.h"
#include "lnp.h"
#include <algorithm>
#include <emmintrin.h>
#include <filesystem>

CompilationUnitFile::CompilationUnitFile(DebugInfoEntry *cu) noexcept
    : m_addr_ranges(), m_name(), m_ltes(), fns(), cu_die(cu)
{
}

CompilationUnitFile::CompilationUnitFile(CompilationUnitFile &&o) noexcept
    : m_addr_ranges(std::move(o.m_addr_ranges)), m_name(o.m_name), pc_boundaries(o.pc_boundaries),
      line_header(std::move(o.line_header)), m_ltes(std::move(o.m_ltes)), fns(std::move(o.fns)), cu_die(o.cu_die)
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
  line_header = std::move(o.line_header);
  m_ltes = std::move(o.m_ltes);
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

TPtr<void>
CompilationUnitFile::low_pc() const noexcept
{
  return pc_boundaries.low;
}
TPtr<void>
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

bool
CompilationUnitFile::last_added_addr_valid() const noexcept
{
  return m_addr_ranges.back().is_valid();
}

void
CompilationUnitFile::set_linetable_header(std::unique_ptr<LineHeader> &&header) noexcept
{
  line_header = std::move(header);
}

void
CompilationUnitFile::set_linetable(LineTable &&lte) noexcept
{
  m_ltes = std::move(lte);
}

void
CompilationUnitFile::set_boundaries() noexcept
{
  if (!m_addr_ranges.empty())
    pc_boundaries = AddressRange{.low = m_addr_ranges.front().low, .high = m_addr_ranges.back().high};
  else
    pc_boundaries = AddressRange{.low = m_ltes.front().pc, .high = m_ltes.back().pc + 1};
}

const LineTable &
CompilationUnitFile::line_table() const noexcept
{
  return m_ltes;
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
                                 [](FnSym &fn, TPtr<void> start) { return fn.start < start; });
  fns.insert(it_pos, sym);
}

const FunctionSymbol *
CompilationUnitFile::find_subprogram(TPtr<void> addr) const noexcept
{
  using FnSym = FunctionSymbol;
  const auto sym = std::lower_bound(fns.cbegin(), fns.cend(), addr.offset(1),
                                    [](const FnSym &l, TPtr<void> addr) { return l.end < addr; });
  if (sym != std::end(fns)) {
    ASSERT(sym->start.get() <= addr.get() && addr.get() < sym->end.get(),
           "Found unexpectedly the wrong FunctionSymbol when searching for {}. Sym '{}' [{}..{}]", addr, sym->name,
           sym->start, sym->end);
    return sym.base();
  } else {
    return nullptr;
  }
}

std::string_view
CompilationUnitFile::file(u32 index) const noexcept
{
  ASSERT(index < line_header->file_names.size(), "No file in this CU with that index");
  return line_header->file_names[index].file_name;
}