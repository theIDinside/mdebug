/** LICENSE TEMPLATE */
#include "index_die_names.h"
#include "utils/logger.h"
// system
#include <algorithm>
// mdb
#include <symbolication/cu_symbol_info.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/dwarf/die_ref.h>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/dwarf/name_index.h>
#include <symbolication/dwarf/rnglists.h>
#include <symbolication/dwarf_attribute_value.h>
#include <symbolication/dwarf_defs.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/interval_map.h>
#include <utils/scope_defer.h>
#include <utils/thread_pool.h>

namespace mdb::sym::dw {

IndexingTask::IndexingTask(ObjectFile *objectFile, std::span<UnitData *> compUnits) noexcept
    : mObjectFile(objectFile), mCompUnitsToIndex(compUnits.begin(), compUnits.end())
{
}

/*static*/ std::vector<IndexingTask *>
IndexingTask::CreateIndexingJobs(ObjectFile *obj, std::pmr::memory_resource *taskGroupAllocator)
{
  std::pmr::vector<std::pmr::vector<sym::dw::UnitData *>> works{ taskGroupAllocator };

  std::pmr::vector<sym::dw::UnitData *> sortedBySize{ taskGroupAllocator };
  mdb::CopyTo(obj->GetAllCompileUnits(), sortedBySize);

  std::sort(
    sortedBySize.begin(), sortedBySize.end(), [](auto a, auto b) { return a->UnitSize() > b->UnitSize(); });

  std::vector<IndexingTask *> tasks;
  std::vector<u64> taskSize;

  const auto workerCount = mdb::ThreadPool::GetGlobalPool()->WorkerCount();
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
      tasks.push_back(new IndexingTask{ obj, w });
    }
  }

  ASSERT(acc == sortedBySize.size(), "Work splitting algorithm incorrect");

  return tasks;
}

static bool
IsMethod(UnitData *compilationUnit, const DieMetaData &die)
{
  DieReference ref{ compilationUnit, &die };
  auto objectFile = compilationUnit->GetObjectFile();
  while (ref.IsValid()) {
    const auto &abbreviations = ref.GetAbbreviation();
    auto reader = ref.GetReader();
    bool consideredComplete = true;

    for (auto it = std::cbegin(abbreviations.mAttributes);
      it != std::cend(abbreviations.mAttributes) && consideredComplete;
      ++it) {
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
IndexingTask::ExecuteTask(std::pmr::memory_resource *) noexcept
{

  using NameSet = std::vector<NameIndex::NameDieTuple>;
  using NameTypeSet = std::vector<NameIndex::NameTypeDieTuple>;

  auto sz = 0ul;
  for (const auto unit : mCompUnitsToIndex) {
    sz += unit->GetHeader().CompilationUnitSize();
  }

  PROFILE_SCOPE_END_ARGS("IndexingTask::ExecuteTask",
    "indexing",
    PEARG("units", mCompUnitsToIndex.size()),
    PEARG("unit_data_size", sz));

  NameSet freeFunctions;
  NameSet methods;
  NameTypeSet types;
  NameSet globalVariables;
  NameSet namespaces;

  freeFunctions.reserve(10000);
  methods.reserve(200000);
  types.reserve(100000);
  globalVariables.reserve(10000);
  namespaces.reserve(1000);

  std::vector<sym::dw::UnitData *> followedReferences{};
  std::vector<sym::dw::UnitData *> typeUnits{};
  ScopedDefer clear_metadata{ [&]() {
    for (auto &comp_unit : mCompUnitsToIndex) {
      comp_unit->ClearLoadedCache();
    }

    for (auto cu : followedReferences) {
      cu->ClearLoadedCache();
    }
  } };

  for (auto compileUnit : mCompUnitsToIndex) {
    PROFILE_SCOPE_ARGS("Index Compilation Unit", "indexing", PEARG("cu", compileUnit->SectionOffset()));
    std::vector<i64> implicit_consts;
    const auto &dies = compileUnit->GetDies();
    if (dies.front().mTag == DwarfTag::DW_TAG_type_unit) {
      DBGLOG(core, "DWARF Unit is a type unit: {}", compileUnit->SectionOffset());
      typeUnits.push_back(compileUnit);
    }

    UnitReader reader{ compileUnit };
    auto dieIndex = -1;
    for (const auto &die : dies) {
      ++dieIndex;
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

      const auto &abb = compileUnit->GetAbbreviation(die.mAbbreviationCode);

      const char *name = nullptr;
      const char *mangledName = nullptr;
      auto addrRepresentable = false;
      auto isDecl = false;
      auto isSuperScopeVariable = false;
      auto hasLocation = false;
      reader.SeekDie(die);
      for (const auto &value : abb.mAttributes) {
        switch (value.mName) {
        case Attribute::DW_AT_decl_file: {
          reader.SkipAttribute(value);
        } break;
        case Attribute::DW_AT_decl_line: {
          reader.SkipAttribute(value);
        } break;
        // register name
        case Attribute::DW_AT_name: {
          auto attr = ReadAttributeValue(reader, value, abb.mImplicitConsts);
          name = attr.AsCString();
        } break;
        case Attribute::DW_AT_linkage_name: {
          auto attr = ReadAttributeValue(reader, value, abb.mImplicitConsts);
          mangledName = attr.AsCString();
        } break;
        // is address-representable?
        case Attribute::DW_AT_low_pc:
          [[fallthrough]];
        case Attribute::DW_AT_high_pc:
          [[fallthrough]];
        case Attribute::DW_AT_entry_pc:
          [[fallthrough]];
        case Attribute::DW_AT_ranges:
          addrRepresentable = true;
          reader.SkipAttribute(value);
          break;
        // is global or static value?
        case Attribute::DW_AT_location:
        case Attribute::DW_AT_const_value:
          hasLocation = true;
          isSuperScopeVariable = die.IsSuperScopeVariable();
          reader.SkipAttribute(value);
          break;
        case Attribute::DW_AT_declaration:
          isDecl = true;
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
              UnitReader innerReader{ refUnit, ref };
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
        if (name && hasLocation && isSuperScopeVariable) {
          globalVariables.push_back({ name, dieIndex, compileUnit });
          if (mangledName && mangledName != name) {
            globalVariables.push_back({ mangledName, dieIndex, compileUnit });
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
        if (name && !isDecl) {
          types.push_back({ name, dieIndex, compileUnit, 0 });
        }
        if (mangledName && !isDecl) {
          types.push_back({ mangledName, dieIndex, compileUnit, 0 });
        }
      } break;
      case DwarfTag::DW_TAG_inlined_subroutine: // 0x1d 0x2e
      case DwarfTag::DW_TAG_subprogram: {
        if (!addrRepresentable) {
          break;
        }
        bool isMemberFunction = false;
        if (name) {
          isMemberFunction = IsMethod(compileUnit, die);
          if (isMemberFunction) {
            methods.push_back({ name, dieIndex, compileUnit });
          } else {
            freeFunctions.push_back({ name, dieIndex, compileUnit });
          }
        }

        if (mangledName && mangledName != name) {
          if (isMemberFunction) {
            methods.push_back({ mangledName, dieIndex, compileUnit });
          } else {
            freeFunctions.push_back({ mangledName, dieIndex, compileUnit });
          }
        }
      } break;
      case DwarfTag::DW_TAG_namespace:
      case DwarfTag::DW_TAG_imported_declaration:
        if (name) {
          namespaces.push_back({ name, dieIndex, compileUnit });
        }
        break;
      default:
        continue;
      }
    }
  }

  auto idx = mObjectFile->GetNameIndex();
  idx->mNamespaces.Merge(namespaces);
  idx->mFreeFunctions.Merge(freeFunctions);
  idx->mGlobalVariables.Merge(globalVariables);
  idx->mMethods.Merge(methods);
  idx->mTypes.MergeTypes(mObjectFile->GetTypeStorage(), types);

  if (!typeUnits.empty()) {
    mObjectFile->AddTypeUnits(typeUnits);
  }
}

sym::PartialCompilationUnitSymbolInfo
IndexingTask::InitPartialCompilationUnit(UnitData *partial_cu, const DieMetaData &) noexcept
{
  // TODO("IndexingTask::initialize_partial_compilation_unit not yet implemented");
  return sym::PartialCompilationUnitSymbolInfo{ partial_cu };
}
}; // namespace mdb::sym::dw