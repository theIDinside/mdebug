#include "dwarf_unit_data.h"
#include "lib/arena_allocator.h"
#include "symbolication/cu_symbol_info.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/rnglists.h"
#include <chrono>
#include <ranges>
#include <symbolication/objfile.h>
#include <utils/thread_pool.h>
namespace sym::dw {

UnitDataTask::UnitDataTask(ObjectFile *obj, std::span<UnitHeader> headers) noexcept
    : obj(obj), mCompilationUnitsToParse(headers.begin(), headers.end())
{
}

static void
ProcessCompilationUnitBoundary(const AttributeValue &ranges_offset, sym::CompilationUnit &src) noexcept
{
  auto cu = src.get_dwarf_unit();
  const auto version = cu->header().version();
  ASSERT(version == DwarfVersion::D4 || version == DwarfVersion::D5, "Dwarf version not supported");
  auto elf = cu->GetObjectFile()->GetElf();
  if (version == DwarfVersion::D4) {
    auto byte_ptr = reinterpret_cast<const u64 *>(elf->debug_ranges->GetPointer(ranges_offset.address()));
    auto lowest = UINTMAX_MAX;
    auto highest = 0ul;
    auto start = 0ul;
    auto end = 1ul;
    bool found_a_range = false;
    while (true) {
      start = *byte_ptr++;
      end = *byte_ptr++;
      if (start == 0) {
        // garbage garbled DW_AT_ranges data is *super* common, and when start == 0.
        // after some research of the DWARF data (using llvm-dwarfdump), it seems to be the case that
        // DW_AT_ranges values with start=0, end=N, are actually some form of duplicate DIE's that has not been
        // de-duplicated. Which is shite.
        if (end == 0) {
          break;
        } else {
          continue;
        }
      } else {
        lowest = std::min(start, lowest);
        highest = std::max(end, highest);
        found_a_range = true;
      }
    }
    if (found_a_range) {
      src.SetAddressBoundary(lowest, highest);
    }
  } else if (version == DwarfVersion::D5) {
    ASSERT(elf->debug_rnglists != nullptr,
           "DWARF Version 5 requires DW_AT_ranges in a .debug_aranges but no such section has been found");
    if (ranges_offset.form == AttributeForm::DW_FORM_sec_offset) {
      auto addr_range = sym::dw::read_boundaries(elf->debug_rnglists, ranges_offset.unsigned_value());
      src.SetAddressBoundary(addr_range.StartPc(), addr_range.EndPc());
    } else {
      auto ranges =
        sym::dw::read_boundaries(*cu, ResolvedRangeListOffset::make(*cu, ranges_offset.unsigned_value()));
      AddrPtr lowpc = static_cast<u64>(-1);
      AddrPtr highpc = nullptr;
      for (const auto [low, high] : ranges) {
        lowpc = std::min(low, lowpc);
        highpc = std::max(high, highpc);
      }
      src.SetAddressBoundary(lowpc, highpc);
    }
  }
}

void
UnitDataTask::execute_task(std::pmr::memory_resource* mGroupTemporaryAllocator) noexcept
{
  std::vector<UnitData *> result;
  for (const auto &header : mCompilationUnitsToParse) {
    const auto start = std::chrono::high_resolution_clock::now();
    auto unit_data = prepare_unit_data(obj, header);
    const auto time =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
        .count();
    DBGLOG(perf, "prepared unit data for 0x{:x} in {}us", header.debug_info_offset(), time);
    result.push_back(unit_data);
  }

  std::vector<CompilationUnit *> compilationUnits;

  for (auto dwarfUnit :
       result | std::views::filter([](UnitData *unit) { return unit->IsCompilationUnitLike(); })) {
    UnitReader reader{dwarfUnit};

    if (dwarfUnit->header().get_unit_type() == DwarfUnitType::DW_UT_partial) {
      DBGLOG(dwarf, "partial unit supported not implemented, skipped 0x{:x}", dwarfUnit->SectionOffset());
      continue;
    }

    const auto die_sec_offset = reader.sec_offset();
    const auto [abbr_code, uleb_sz] = reader.read_uleb128();
    auto &abbrs = dwarfUnit->get_abbreviation(abbr_code);
    const auto unitDie = DieMetaData::create_die(die_sec_offset, abbrs, NONE_INDEX, uleb_sz, NONE_INDEX);
    sym::CompilationUnit *newCompilationUnit = new CompilationUnit{dwarfUnit};

    std::optional<AddrPtr> low;
    std::optional<AddrPtr> high;

    for (const auto &abbr : abbrs.attributes) {
      switch (abbr.name) {
      case Attribute::DW_AT_stmt_list: {
        const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
        const auto offset = attr.address();
        auto header = dw::LNPHeader::ReadLineNumberProgramHeader(obj, offset);
        newCompilationUnit->ProcessSourceCodeFiles(header);
        break;
      }
      case Attribute::DW_AT_name: {
        const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
        const auto name = attr.string();
        newCompilationUnit->set_name(name);
        break;
      }
      case Attribute::DW_AT_ranges: {
        const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
        ProcessCompilationUnitBoundary(attr, *newCompilationUnit);
      } break;
      case Attribute::DW_AT_low_pc: {
        const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
        if (!low) {
          low = attr.address();
        }
      } break;
      case Attribute::DW_AT_high_pc: {
        const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
        high = attr.address();
      } break;
      case Attribute::DW_AT_import:
        [[fallthrough]];
      default:
        reader.skip_attribute(abbr);
        break;
      }
    }

    const auto boundary_seen = (low.has_value() && high.has_value());
    if (!newCompilationUnit->HasKnownAddressBoundary() && boundary_seen) {
      newCompilationUnit->SetAddressBoundary(low.value(), low.value() + high.value());
    }

    compilationUnits.push_back(newCompilationUnit);
  }

  obj->SetCompileUnitData(result);
  obj->AddInitializedCompileUnits(compilationUnits);
}

/* static */
std::vector<UnitDataTask *>
UnitDataTask::CreateParsingJobs(ObjectFile *obj, std::pmr::memory_resource* allocator) noexcept
{
  const auto sectionSize = obj->GetElf()->debug_info->Size();
  UnitHeadersRead headerRead;
  headerRead.ReadUnitHeaders(obj);
  std::pmr::vector<std::pmr::vector<sym::dw::UnitHeader>> works{allocator};

  std::pmr::vector<sym::dw::UnitHeader> sortedBySize{allocator};
  utils::copy_to(headerRead.Headers(), sortedBySize);

  std::sort(sortedBySize.begin(), sortedBySize.end(),
            [](const UnitHeader &a, const UnitHeader &b) { return a.cu_size() > b.cu_size(); });

  std::vector<UnitDataTask *> tasks;
  std::pmr::vector<u64> taskSize{allocator};

  const auto workerCount = utils::ThreadPool::get_global_pool()->worker_count();
  works.resize(workerCount, {});
  tasks.reserve(workerCount);
  taskSize.resize(workerCount, 0);

  for (auto header : sortedBySize) {
    // Find the subgroup with the smallest current total
    const u64 minIndex = std::distance(taskSize.begin(), std::min_element(taskSize.begin(), taskSize.end()));

    // Assign the number to this subgroup
    works[minIndex].push_back(header);
    taskSize[minIndex] += header.cu_size();
  }

  auto acc = 0u;
  for (auto &w : works) {
    if (!w.empty()) {
      acc += w.size();
      tasks.push_back(new UnitDataTask{obj, std::span{w}});
    }
  }

  ASSERT(acc == sortedBySize.size(), "Work splitting algorithm incorrect");

  return tasks;
}


} // namespace sym::dw