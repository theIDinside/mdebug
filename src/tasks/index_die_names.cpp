/** LICENSE TEMPLATE */
#include "index_die_names.h"
// system
#include <algorithm>
// mdb
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/dwarf/die_ref.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/dwarf/name_index.h>
#include <symbolication/dwarf/rnglists.h>
#include <symbolication/dwarf_defs.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/interval_map.h>
#include <utils/scope_defer.h>
#include <utils/thread_pool.h>

namespace sym::dw {

IndexingTask::IndexingTask(ObjectFile *objectFile, std::span<UnitData *> compUnits) noexcept
    : mObjectFile(objectFile), mCompUnitsToIndex(compUnits.begin(), compUnits.end())
{
}

/*static*/ std::vector<IndexingTask *>
IndexingTask::CreateIndexingJobs(ObjectFile *obj, std::pmr::memory_resource *taskGroupAllocator)
{
  std::pmr::vector<std::pmr::vector<sym::dw::UnitData *>> works{taskGroupAllocator};

  std::pmr::vector<sym::dw::UnitData *> sortedBySize{taskGroupAllocator};
  utils::CopyTo(obj->GetAllCompileUnits(), sortedBySize);

  std::sort(sortedBySize.begin(), sortedBySize.end(),
            [](auto a, auto b) { return a->UnitSize() > b->UnitSize(); });

  std::vector<IndexingTask *> tasks;
  std::vector<u64> taskSize;

  const auto workerCount = utils::ThreadPool::GetGlobalPool()->WorkerCount();
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

static bool
IsMethod(UnitData *compilationUnit, const DieMetaData &die)
{
  DieReference ref{compilationUnit, &die};
  auto objectFile = compilationUnit->GetObjectFile();
  while (ref.IsValid()) {
    const auto &abbreviations = ref.GetAbbreviation();
    auto reader = ref.GetReader();
    bool consideredComplete = true;

    for (auto it = std::cbegin(abbreviations.mAttributes);
         it != std::cend(abbreviations.mAttributes) && consideredComplete; ++it) {
      switch (it->mName) {
      case Attribute::DW_AT_specification:
        [[fallthrough]];
      case Attribute::DW_AT_abstract_origin: {
        consideredComplete = false;
        const auto offset = ReadAttributeValue(reader, *it, abbreviations.mImplicitConsts).AsUnsignedValue();
        UnitData *originCu = objectFile->GetCompileUnitFromOffset(offset);
        ref = originCu->GetDieReferenceByOffset(offset);
      } break;
      default:
        reader.SkipAttribute(*it);
        break;
      }
    }

    if (consideredComplete) {
      switch (ref.GetDie()->GetParent()->mTag) {
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
IndexingTask::ExecuteTask(std::pmr::memory_resource *temporaryAllocator) noexcept
{
  using NameSet = std::vector<NameIndex::NameDieTuple>;
  using NameTypeSet = std::vector<NameIndex::NameTypeDieTuple>;

  auto sz = 0;
  for (const auto unit : mCompUnitsToIndex) {
    sz += unit->header().CompilationUnitSize();
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
    for (auto &comp_unit : mCompUnitsToIndex) {
      comp_unit->ClearLoadedCache();
    }

    for (auto cu : followed_references) {
      cu->ClearLoadedCache();
    }
  }};

  for (auto comp_unit : mCompUnitsToIndex) {
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<i64> implicit_consts;
    const auto &dies = comp_unit->GetDies();
    if (dies.front().mTag == DwarfTag::DW_TAG_type_unit) {
      DBGLOG(core, "DWARF Unit is a type unit: 0x{:x}", comp_unit->SectionOffset());
      type_units.push_back(comp_unit);
    }

    UnitReader reader{comp_unit};
    auto die_index = -1;
    for (const auto &die : dies) {
      ++die_index;
      // work only on dies, that can have a name associated (via DW_AT_name attribute)
      switch (die.mTag) {
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

      const auto &abb = comp_unit->GetAbbreviation(die.mAbbreviationCode);

      const char *name = nullptr;
      const char *mangled_name = nullptr;
      auto addr_representable = false;
      auto is_decl = false;
      auto is_super_scope_var = false;
      auto has_loc = false;
      auto decl_file = 0u;
      auto decl_line = 0u;
      reader.SeekDie(die);
      for (const auto &value : abb.mAttributes) {
        switch (value.mName) {
        case Attribute::DW_AT_decl_file: {
          decl_file = ReadAttributeValue(reader, value, abb.mImplicitConsts).AsUnsignedValue();
        } break;
        case Attribute::DW_AT_decl_line: {
          decl_line = ReadAttributeValue(reader, value, abb.mImplicitConsts).AsUnsignedValue();
        } break;
        // register name
        case Attribute::DW_AT_name: {
          auto attr = ReadAttributeValue(reader, value, abb.mImplicitConsts);
          name = attr.AsCString();
        } break;
        case Attribute::DW_AT_linkage_name: {
          auto attr = ReadAttributeValue(reader, value, abb.mImplicitConsts);
          mangled_name = attr.AsCString();
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
          reader.SkipAttribute(value);
          break;
        // is global or static value?
        case Attribute::DW_AT_location:
        case Attribute::DW_AT_const_value:
          has_loc = true;
          is_super_scope_var = die.IsSuperScopeVariable();
          reader.SkipAttribute(value);
          break;
        case Attribute::DW_AT_declaration:
          is_decl = true;
          reader.SkipAttribute(value);
          break;
        case Attribute::DW_AT_specification:
          [[fallthrough]];
        case Attribute::DW_AT_abstract_origin: {
          switch (die.mTag) {
          case DwarfTag::DW_TAG_subprogram:
            [[fallthrough]];
          case DwarfTag::DW_TAG_inlined_subroutine: {
            // We're doing name indexing.. we only care to find the name of referenced DIE, really.
            auto ref = ReadAttributeValue(reader, value, abb.mImplicitConsts).AsUnsignedValue();
            while (!name) {
              auto refUnit = mObjectFile->GetCompileUnitFromOffset(ref);
              UnitReader innerReader{refUnit, ref};
              const auto [abbr_code, uleb_sz] = innerReader.DecodeULEB128();
              const auto &remoteAbbrev = refUnit->GetAbbreviation(abbr_code);
              u64 newRef = 0;
              for (const auto &abbrev : remoteAbbrev.mAttributes) {
                switch (abbrev.mName) {
                case Attribute::DW_AT_name:
                  name = ReadAttributeValue(innerReader, abbrev, remoteAbbrev.mImplicitConsts).AsCString();
                  break;
                case Attribute::DW_AT_specification:
                  [[fallthrough]];
                case Attribute::DW_AT_abstract_origin:
                  newRef = ReadAttributeValue(innerReader, abbrev, remoteAbbrev.mImplicitConsts).AsUnsignedValue();
                  break;
                default:
                  innerReader.SkipAttribute(abbrev);
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
          reader.SkipAttribute(value);
          break;
        }
      }

      switch (die.mTag) {
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
  auto idx = mObjectFile->GetNameIndex();
  idx->mNamespaces.Merge(namespaces);
  idx->mFreeFunctions.Merge(free_functions);
  idx->mGlobalVariables.Merge(global_variables);
  idx->mMethods.Merge(methods);
  idx->mTypes.MergeTypes(mObjectFile->GetTypeStorage(), types);

  if (!type_units.empty()) {
    mObjectFile->AddTypeUnits(type_units);
  }
}

sym::PartialCompilationUnitSymbolInfo
IndexingTask::InitPartialCompilationUnit(UnitData *partial_cu, const DieMetaData &) noexcept
{
  // TODO("IndexingTask::initialize_partial_compilation_unit not yet implemented");
  return sym::PartialCompilationUnitSymbolInfo{partial_cu};
}
}; // namespace sym::dw