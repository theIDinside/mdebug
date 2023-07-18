#include "type.h"
#include "block.h"
#include "dwarf.h"
#include <emmintrin.h>
#include <filesystem>

CompilationUnitFile::CompilationUnitFile(DebugInfoEntry *cu) noexcept
    : m_addr_ranges(), m_name(), m_ltes(), functions(), cu_die(cu)
{
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

void
CompilationUnitFile::add_function(std::string_view fn_name, FunctionSymbol sym) noexcept
{
  functions[fn_name] = sym;
}

FunctionSymbol *
CompilationUnitFile::find_subprogram(TPtr<void> addr) noexcept
{
  for (const auto &[name, fn] : functions) {
    if (addr >= fn.start && addr <= fn.end)
      return &functions[name];
  }
  return nullptr;
}