/** LICENSE TEMPLATE */
#include "dwarf_unit_data.h"
#include "symbolication/cu_symbol_info.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf/rnglists.h"
#include "utils/scope_defer.h"
#include <chrono>
#include <ranges>
#include <ratio>
#include <symbolication/objfile.h>
#include <utils/thread_pool.h>
namespace mdb::sym::dw {

UnitDataTask::UnitDataTask(ObjectFile *obj, std::span<UnitHeader> headers) noexcept
    : obj(obj), mCompilationUnitsToParse(headers.begin(), headers.end())
{
}

static void
ProcessCompilationUnitBoundary(const AttributeValue &ranges_offset, sym::CompilationUnit &src) noexcept
{
  auto cu = src.get_dwarf_unit();
  const auto version = cu->header().Version();
  ASSERT(version == DwarfVersion::D4 || version == DwarfVersion::D5, "Dwarf version not supported");
  auto elf = cu->GetObjectFile()->GetElf();

  if (version == DwarfVersion::D4) {
    auto byte_ptr = reinterpret_cast<const u64 *>(elf->debug_ranges->GetPointer(ranges_offset.AsAddress()));
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
        if (start != 1 && end != 1) {
          lowest = std::min(start, lowest);
          highest = std::max(end, highest);
          found_a_range = true;
        }
      }
    }
    if (found_a_range) {
      src.SetAddressBoundary(lowest, highest);
    }
  } else if (version == DwarfVersion::D5) {
    ASSERT(elf->debug_rnglists != nullptr,
           "DWARF Version 5 requires DW_AT_ranges in a .debug_aranges but no such section has been found");
    if (ranges_offset.form == AttributeForm::DW_FORM_sec_offset) {
      auto addr_range = sym::dw::read_boundaries(elf->debug_rnglists, ranges_offset.AsUnsignedValue());
      src.SetAddressBoundary(addr_range.StartPc(), addr_range.EndPc());
    } else {
      auto ranges =
        sym::dw::read_boundaries(*cu, ResolvedRangeListOffset::make(*cu, ranges_offset.AsUnsignedValue()));
      AddrPtr lowpc = static_cast<u64>(-1);
      AddrPtr highpc = nullptr;
      for (const auto [low, high] : ranges) {
        lowpc = std::min(low, lowpc);
        highpc = std::max(high, highpc);
      }
      src.SetAddressRanges(std::move(ranges));
      src.SetAddressBoundary(lowpc, highpc);
    }
  }
}

void
UnitDataTask::ExecuteTask(std::pmr::memory_resource *mGroupTemporaryAllocator) noexcept
{
  PROFILE_SCOPE_END_ARGS("UnitDataTask::ExecuteTask", "unitdata", PEARG("units", mCompilationUnitsToParse.size()));

  std::vector<UnitData *> result;
  result.reserve(mCompilationUnitsToParse.size());
  for (const auto &header : mCompilationUnitsToParse) {
    auto unit_data = PrepareUnitData(obj, header);
    result.push_back(unit_data);
  }

  std::vector<sym::CompilationUnit *> compilationUnits;

  for (auto dwarfUnit :
       result | std::views::filter([](UnitData *unit) { return unit->IsCompilationUnitLike(); })) {
    UnitReader reader{dwarfUnit};

    if (dwarfUnit->header().GetUnitType() == DwarfUnitType::DW_UT_partial) {
      DBGLOG(dwarf, "partial unit supported not implemented, skipped {}", dwarfUnit->SectionOffset());
      continue;
    }

    const auto [abbr_code, uleb_sz] = reader.DecodeULEB128();
    auto &abbrs = dwarfUnit->GetAbbreviation(abbr_code);
    auto *newCompilationUnit = new sym::CompilationUnit{dwarfUnit};

    std::optional<AddrPtr> low;
    std::optional<AddrPtr> high;

    for (const auto &abbr : abbrs.mAttributes) {
      switch (abbr.mName) {
      case Attribute::DW_AT_stmt_list: {
        const auto attr = ReadAttributeValue(reader, abbr, abbrs.mImplicitConsts);
        const auto offset = attr.AsAddress();
        auto header = dw::LNPHeader::ReadLineNumberProgramHeader(obj, offset);
        newCompilationUnit->ProcessSourceCodeFiles(header);
        break;
      }
      case Attribute::DW_AT_name: {
        const auto attr = ReadAttributeValue(reader, abbr, abbrs.mImplicitConsts);
        const auto name = attr.AsCString();
        newCompilationUnit->SetUnitName(name);
        break;
      }
      case Attribute::DW_AT_ranges: {
        const auto attr = ReadAttributeValue(reader, abbr, abbrs.mImplicitConsts);
        ProcessCompilationUnitBoundary(attr, *newCompilationUnit);
      } break;
      case Attribute::DW_AT_low_pc: {
        const auto attr = ReadAttributeValue(reader, abbr, abbrs.mImplicitConsts);
        if (!low) {
          low = attr.AsAddress();
        }
      } break;
      case Attribute::DW_AT_high_pc: {
        const auto attr = ReadAttributeValue(reader, abbr, abbrs.mImplicitConsts);
        high = attr.AsAddress();
      } break;
      case Attribute::DW_AT_import:
        [[fallthrough]];
      default:
        reader.SkipAttribute(abbr);
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
UnitDataTask::CreateParsingJobs(ObjectFile *obj, std::pmr::memory_resource *allocator) noexcept
{
  UnitHeadersRead headerRead;
  headerRead.ReadUnitHeaders(obj);
  std::pmr::vector<std::pmr::vector<sym::dw::UnitHeader>> works{allocator};

  std::pmr::vector<sym::dw::UnitHeader> sortedBySize{allocator};
  mdb::CopyTo(headerRead.Headers(), sortedBySize);

  std::sort(sortedBySize.begin(), sortedBySize.end(), [](const UnitHeader &a, const UnitHeader &b) {
    return a.CompilationUnitSize() > b.CompilationUnitSize();
  });

  std::vector<UnitDataTask *> tasks;
  std::pmr::vector<u64> taskSize{allocator};

  const auto workerCount = mdb::ThreadPool::GetGlobalPool()->WorkerCount();
  works.resize(workerCount, {});
  tasks.reserve(workerCount);
  taskSize.resize(workerCount, 0);

  for (auto header : sortedBySize) {
    // Find the subgroup with the smallest current total
    const u64 minIndex = std::distance(taskSize.begin(), std::min_element(taskSize.begin(), taskSize.end()));

    // Assign the number to this subgroup
    works[minIndex].push_back(header);
    taskSize[minIndex] += header.CompilationUnitSize();
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

} // namespace mdb::sym::dw