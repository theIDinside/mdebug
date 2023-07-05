#include "type.h"
#include "block.h"
#include <filesystem>

CompilationUnitFile::CompilationUnitFile(std::string_view name, AddrRanges &&addr_ranges,
                                         LineTable &&lt_ents) noexcept
    : m_name(name), m_addr_ranges(std::move(addr_ranges)), m_ltes(std::move(lt_ents))
{
  pc_boundaries = AddressRange{.low = m_addr_ranges.front().low, .high = m_addr_ranges.back().high};
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