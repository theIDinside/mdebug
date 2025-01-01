#include "index_die_names.h"
#include "../symbolication/cu_symbol_info.h"
#include "../symbolication/dwarf.h"
#include "../symbolication/dwarf/debug_info_reader.h"
#include "../symbolication/dwarf/lnp.h"
#include "../symbolication/dwarf/name_index.h"
#include "../symbolication/elf.h"
#include "../symbolication/objfile.h"
#include "../utils/thread_pool.h"
#include "lib/arena_allocator.h"
#include "symbolication/dwarf/die_ref.h"
#include "symbolication/dwarf/rnglists.h"
#include "symbolication/dwarf_defs.h"
#include "utils/interval_map.h"
#include "utils/scope_defer.h"
#include <algorithm>
#include <cstdint>

namespace sym::dw {

IndexingTask::IndexingTask(ObjectFile *obj, std::span<UnitData *> cus_to_index) noexcept
    : obj(obj), cus_to_index(cus_to_index.begin(), cus_to_index.end())
{
}

/*static*/ std::vector<IndexingTask *>
IndexingTask::CreateIndexingJobs(ObjectFile *obj, std::pmr::memory_resource* taskGroupAllocator)
{
  std::pmr::vector<std::pmr::vector<sym::dw::UnitData *>> works{taskGroupAllocator};

  std::pmr::vector<sym::dw::UnitData *> sortedBySize{taskGroupAllocator};
  utils::copy_to(obj->GetAllCompileUnits(), sortedBySize);

  std::sort(sortedBySize.begin(), sortedBySize.end(),
            [](auto a, auto b) { return a->UnitSize() > b->UnitSize(); });

  std::vector<IndexingTask *> tasks;
  std::vector<u64> taskSize;

  const auto workerCount = utils::ThreadPool::get_global_pool()->worker_count();
  works.resize(workerCount, {});
  tasks.reserve(workerCount);
  taskSize.resize(workerCount, 0);

  for (auto unit : sortedBySize) {
    // Find the subgroup with the smallest current total
    const u64 minIndex = std::distance(taskSize.begin(), std::min_element(taskSize.begin(), taskSize.end()));

    // Assign the number to this subgroup
    works[minIndex].push_back(unit);
    taskSize[minIndex] += unit->UnitSize();
  }

  auto acc = 0u;
  for (auto &w : works) {
    if (!w.empty()) {
      acc += w.size();
      tasks.push_back(new IndexingTask{obj, w});
    }
  }

  ASSERT(acc == sortedBySize.size(), "Work splitting algorithm incorrect");

  return tasks;
}

template <Attribute... Attrs>
std::vector<AttributeValue>
read_values(UnitData &cu, const DieMetaData &die) noexcept
{
  UnitReader reader{&cu};
  const auto &attrs = cu.get_abbreviation(die.abbreviation_code);
  reader.SeekDie(die);
  std::vector<AttributeValue> attribute_values{};
  for (auto attribute : attrs.attributes) {
    const auto value = read_attribute_value(reader, attribute, attrs.implicit_consts);
    if (((value.name == Attrs) || ...)) {
      attribute_values.push_back(value);
    }
  }
  return attribute_values;
}

static bool
IsMethod(UnitData *compilationUnit, const DieMetaData &die)
{
  DieReference ref{compilationUnit, &die};
  auto objectFile = compilationUnit->GetObjectFile();
  while (ref.IsValid()) {
    const auto &abbreviations = ref.GetAbbreviation();
    auto reader = ref.GetReader();
    bool consideredComplete = true;

    for (auto it = std::cbegin(abbreviations.attributes);
         it != std::cend(abbreviations.attributes) && consideredComplete; ++it) {
      switch (it->name) {
      case Attribute::DW_AT_specification:
        [[fallthrough]];
      case Attribute::DW_AT_abstract_origin: {
        consideredComplete = false;
        const auto offset = read_attribute_value(reader, *it, abbreviations.implicit_consts).unsigned_value();
        UnitData *originCu = objectFile->GetCompileUnitFromOffset(offset);
        ref = originCu->GetDieReferenceByOffset(offset);
      } break;
      default:
        reader.skip_attribute(*it);
        break;
      }
    }

    if (consideredComplete) {
      switch (ref.GetDie()->parent()->tag) {
      case DwarfTag::DW_TAG_class_type:
        return true;
      case DwarfTag::DW_TAG_structure_type:
        return true;
      default:
        return false;
      }
    }
  }

  return false;
}

void
IndexingTask::execute_task(std::pmr::memory_resource* temporaryAllocator) noexcept
{
  using NameSet = std::vector<NameIndex::NameDieTuple>;
  using NameTypeSet = std::vector<NameIndex::NameTypeDieTuple>;

  auto sz = 0;
  for (const auto unit : cus_to_index) {
    sz += unit->header().cu_size();
  }

  NameSet free_functions;
  NameSet methods;
  NameTypeSet types;
  NameSet global_variables;
  NameSet namespaces;

  free_functions.reserve(10000);
  methods.reserve(200000);
  types.reserve(100000);
  global_variables.reserve(10000);
  namespaces.reserve(1000);

  std::vector<sym::dw::UnitData *> followed_references{};
  std::vector<sym::dw::UnitData *> type_units{};

  ScopedDefer clear_metadata{[&]() {
    for (auto &comp_unit : cus_to_index) {
      comp_unit->ClearLoadedCache();
    }

    for (auto cu : followed_references) {
      cu->ClearLoadedCache();
    }
  }};

  for (auto comp_unit : cus_to_index) {
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<i64> implicit_consts;
    const auto &dies = comp_unit->get_dies();
    if (dies.front().tag == DwarfTag::DW_TAG_type_unit) {
      DBGLOG(core, "DWARF Unit is a type unit: 0x{:x}", comp_unit->SectionOffset());
      type_units.push_back(comp_unit);
    }

    UnitReader reader{comp_unit};
    auto die_index = -1;
    for (const auto &die : dies) {
      ++die_index;
      // work only on dies, that can have a name associated (via DW_AT_name attribute)
      switch (die.tag) {
      case DwarfTag::DW_TAG_array_type:
      case DwarfTag::DW_TAG_class_type:
      case DwarfTag::DW_TAG_entry_point:
      case DwarfTag::DW_TAG_enumeration_type:
      case DwarfTag::DW_TAG_formal_parameter:
      case DwarfTag::DW_TAG_imported_declaration:
      case DwarfTag::DW_TAG_string_type:
      case DwarfTag::DW_TAG_structure_type:
      case DwarfTag::DW_TAG_subroutine_type:
      case DwarfTag::DW_TAG_typedef:
      case DwarfTag::DW_TAG_union_type:
      case DwarfTag::DW_TAG_subprogram:
      case DwarfTag::DW_TAG_inlined_subroutine:
      case DwarfTag::DW_TAG_base_type:
      case DwarfTag::DW_TAG_namespace:
      case DwarfTag::DW_TAG_atomic_type:
      case DwarfTag::DW_TAG_constant:
      case DwarfTag::DW_TAG_variable:
        break;
      default:
        // skip other dies
        continue;
      }

      const auto &abb = comp_unit->get_abbreviation(die.abbreviation_code);

      const char *name = nullptr;
      const char *mangled_name = nullptr;
      auto addr_representable = false;
      auto is_decl = false;
      auto is_super_scope_var = false;
      auto has_loc = false;
      auto decl_file = 0u;
      auto decl_line = 0u;
      reader.SeekDie(die);
      for (const auto &value : abb.attributes) {
        switch (value.name) {
        case Attribute::DW_AT_decl_file: {
          decl_file = read_attribute_value(reader, value, abb.implicit_consts).unsigned_value();
        } break;
        case Attribute::DW_AT_decl_line: {
          decl_line = read_attribute_value(reader, value, abb.implicit_consts).unsigned_value();
        } break;
        // register name
        case Attribute::DW_AT_name: {
          auto attr = read_attribute_value(reader, value, abb.implicit_consts);
          name = attr.string();
        } break;
        case Attribute::DW_AT_linkage_name: {
          auto attr = read_attribute_value(reader, value, abb.implicit_consts);
          mangled_name = attr.string();
        } break;
        // is address-representable?
        case Attribute::DW_AT_low_pc:
          [[fallthrough]];
        case Attribute::DW_AT_high_pc:
          [[fallthrough]];
        case Attribute::DW_AT_entry_pc:
          [[fallthrough]];
        case Attribute::DW_AT_ranges:
          addr_representable = true;
          reader.skip_attribute(value);
          break;
        // is global or static value?
        case Attribute::DW_AT_location:
        case Attribute::DW_AT_const_value:
          has_loc = true;
          is_super_scope_var = die.is_super_scope_variable();
          reader.skip_attribute(value);
          break;
        case Attribute::DW_AT_declaration:
          is_decl = true;
          reader.skip_attribute(value);
          break;
        case Attribute::DW_AT_specification:
          [[fallthrough]];
        case Attribute::DW_AT_abstract_origin: {
          switch (die.tag) {
          case DwarfTag::DW_TAG_subprogram:
            [[fallthrough]];
          case DwarfTag::DW_TAG_inlined_subroutine: {
            // We're doing name indexing.. we only care to find the name of referenced DIE, really.
            auto ref = read_attribute_value(reader, value, abb.implicit_consts).unsigned_value();
            while (!name) {
              auto refUnit = obj->GetCompileUnitFromOffset(ref);
              UnitReader innerReader{refUnit, ref};
              const auto [abbr_code, uleb_sz] = innerReader.read_uleb128();
              const auto &remoteAbbrev = refUnit->get_abbreviation(abbr_code);
              u64 newRef = 0;
              for (const auto &abbrev : remoteAbbrev.attributes) {
                switch (abbrev.name) {
                case Attribute::DW_AT_name:
                  name = read_attribute_value(innerReader, abbrev, remoteAbbrev.implicit_consts).string();
                  break;
                case Attribute::DW_AT_specification:
                  [[fallthrough]];
                case Attribute::DW_AT_abstract_origin:
                  newRef =
                    read_attribute_value(innerReader, abbrev, remoteAbbrev.implicit_consts).unsigned_value();
                  break;
                default:
                  innerReader.skip_attribute(abbrev);
                }
                if (name) {
                  break;
                }
              }

              if (!name && newRef != 0) {
                ref = newRef;
              } else {
                break;
              }
            }
          }
            continue;
          default: {
            goto skip;
          }
          }
        } break;
        default:
        skip:
          reader.skip_attribute(value);
          break;
        }
      }

      switch (die.tag) {
      case DwarfTag::DW_TAG_variable:
        // We only register global variables, everything else wouldn't make sense.
        if (name && has_loc && is_super_scope_var) {
          global_variables.push_back({name, die_index, comp_unit});
          if (mangled_name && mangled_name != name) {
            global_variables.push_back({mangled_name, die_index, comp_unit});
          }
        }
        break;
      case DwarfTag::DW_TAG_array_type:
      case DwarfTag::DW_TAG_base_type:
      case DwarfTag::DW_TAG_class_type:
      case DwarfTag::DW_TAG_constant:
      case DwarfTag::DW_TAG_enumeration_type:
      case DwarfTag::DW_TAG_string_type:
      case DwarfTag::DW_TAG_structure_type:
      case DwarfTag::DW_TAG_subroutine_type:
      case DwarfTag::DW_TAG_typedef:
      case DwarfTag::DW_TAG_union_type:
      case DwarfTag::DW_TAG_unspecified_type: {
        if (name && !is_decl) {
          types.push_back({name, die_index, comp_unit, 0});
        }
        if (mangled_name && !is_decl) {
          types.push_back({mangled_name, die_index, comp_unit, 0});
        }
      } break;
      case DwarfTag::DW_TAG_inlined_subroutine: // 0x1d 0x2e
      case DwarfTag::DW_TAG_subprogram: {
        if (!addr_representable) {
          break;
        }
        bool isMemberFunction = false;
        if (name) {
          isMemberFunction = IsMethod(comp_unit, die);
          if (isMemberFunction) {
            methods.push_back({name, die_index, comp_unit});
          } else {
            free_functions.push_back({name, die_index, comp_unit});
          }
        }

        if (mangled_name && mangled_name != name) {
          if (isMemberFunction) {
            methods.push_back({mangled_name, die_index, comp_unit});
          } else {
            free_functions.push_back({mangled_name, die_index, comp_unit});
          }
        }
      } break;
      case DwarfTag::DW_TAG_namespace:
      case DwarfTag::DW_TAG_imported_declaration:
        if (name) {
          namespaces.push_back({name, die_index, comp_unit});
        }
        break;
      default:
        continue;
      }
    }

    DBGLOG(perf, "unit 0x{:x} indexed in {}", comp_unit->SectionOffset(),
           std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
             .count());
  }
  auto idx = obj->GetNameIndex();
  idx->namespaces.merge(namespaces);
  idx->free_functions.merge(free_functions);
  idx->global_variables.merge(global_variables);
  idx->methods.merge(methods);
  idx->types.merge_types(obj->GetTypeStorage(), types);

  if (!type_units.empty()) {
    obj->AddTypeUnits(type_units);
  }
}

static void
process_cu_boundary(const AttributeValue &ranges_offset, sym::CompilationUnit &src) noexcept
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

sym::PartialCompilationUnitSymbolInfo
IndexingTask::initialize_partial_compilation_unit(UnitData *partial_cu, const DieMetaData &) noexcept
{
  // TODO("IndexingTask::initialize_partial_compilation_unit not yet implemented");
  return sym::PartialCompilationUnitSymbolInfo{partial_cu};
}
}; // namespace sym::dw