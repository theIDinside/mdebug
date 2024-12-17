#include "index_die_names.h"
#include "../symbolication/cu_symbol_info.h"
#include "../symbolication/dwarf.h"
#include "../symbolication/dwarf/debug_info_reader.h"
#include "../symbolication/dwarf/lnp.h"
#include "../symbolication/dwarf/name_index.h"
#include "../symbolication/elf.h"
#include "../symbolication/objfile.h"
#include "../utils/enumerator.h"
#include "../utils/thread_pool.h"
#include "symbolication/dwarf/die_ref.h"
#include "symbolication/dwarf/rnglists.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_defs.h"
#include "utils/scope_defer.h"
#include <algorithm>
#include <cstdint>

namespace sym::dw {

IndexingTask::IndexingTask(ObjectFile *obj, std::span<UnitData *> cus_to_index) noexcept
    : obj(obj), cus_to_index(cus_to_index)
{
}
/*static*/ std::vector<IndexingTask *>
IndexingTask::create_jobs_for(ObjectFile *obj)
{
  const auto cus = std::span{obj->GetAllCompileUnits()};
  const auto work = utils::ThreadPool::calculate_job_sizes(cus);
  std::vector<IndexingTask *> result;
  result.reserve(work.size());
  auto offset = 0;
  for (const auto sz : work) {
    result.push_back(new IndexingTask{obj, cus.subspan(offset, sz)});
    offset += sz;
  }

  return result;
}

template <Attribute... Attrs>
std::vector<AttributeValue>
read_values(UnitData &cu, const DieMetaData &die) noexcept
{
  UnitReader reader{&cu};
  const auto &attrs = cu.get_abbreviation(die.abbreviation_code);
  reader.seek_die(die);
  std::vector<AttributeValue> attribute_values{};
  for (auto attribute : attrs.attributes) {
    const auto value = read_attribute_value(reader, attribute, attrs.implicit_consts);
    if (((value.name == Attrs) || ...)) {
      attribute_values.push_back(value);
    }
  }
  return attribute_values;
}

static auto
IsMemberFunction(std::vector<sym::dw::UnitData *> &followed_references, UnitData &cu,
             const DieMetaData &die) noexcept -> std::tuple<bool, std::optional<std::string_view>>
{
  ASSERT((maybe_null_any_of<DwarfTag::DW_TAG_subprogram, DwarfTag::DW_TAG_inlined_subroutine>(&die)),
         "Asking if die is a member function die when it's not a subprogram die doesn't make sense. "
         "die=0x{:x}, "
         "tag={}",
         die.section_offset, to_str(die.tag));

  UnitReader reader{&cu};
  reader.seek_die(die);

  auto parent_die = die.parent();
  using enum DwarfTag;
  const auto result = maybe_null_any_of<DW_TAG_class_type, DW_TAG_structure_type>(parent_die);
  const auto not_already_added = [id = cu.section_offset()](auto cu) {
    return cu->section_offset() != id;
  };
  for (auto ref = DieReference(&cu, &die).MaybeResolveReference(); ref.IsValid();
       ref = ref.MaybeResolveReference()) {

    if (ref.GetUnitData() != &cu && std::ranges::all_of(followed_references, not_already_added)) {
      ref.GetUnitData()->take_reference();
      followed_references.push_back(ref.GetUnitData());
    }

    const auto result = maybe_null_any_of<DW_TAG_class_type, DW_TAG_structure_type>(ref.GetDie()->parent());
    const auto name = ref.read_attribute(Attribute::DW_AT_name).transform([](auto attr) { return attr.string(); });
    if (result) {
      const auto result = std::make_tuple(true, name);
      return result;
    }
  }
  return std::make_tuple(result, std::nullopt);
}

void
IndexingTask::execute_task() noexcept
{
  using NameSet = std::vector<NameIndex::NameDieTuple>;
  NameSet free_functions;
  NameSet methods;
  NameSet types;
  NameSet global_variables;
  NameSet namespaces;

  std::vector<sym::CompilationUnit> initialized_cus{};
  std::vector<sym::dw::UnitData *> followed_references{};
  std::vector<sym::dw::UnitData *> type_units{};

  ScopedDefer clear_metadata{[&]() {
    for (auto &comp_unit : cus_to_index) {
      comp_unit->clear_die_metadata();
    }

    for (auto cu : followed_references) {
      cu->clear_die_metadata();
    }
  }};

  for (auto comp_unit : cus_to_index) {
    comp_unit->take_reference();
    std::vector<i64> implicit_consts;
    const auto &dies = comp_unit->get_dies();
    if (dies.front().tag == DwarfTag::DW_TAG_compile_unit) {
      sym::CompilationUnit new_cu_file = initialize_compilation_unit(comp_unit, dies.front());
      initialized_cus.push_back(std::move(new_cu_file));
    } else if (dies.front().tag == DwarfTag::DW_TAG_partial_unit) {
      sym::PartialCompilationUnitSymbolInfo partial_cu_file =
        initialize_partial_compilation_unit(comp_unit, dies.front());
    } else if (dies.front().tag == DwarfTag::DW_TAG_type_unit) {
      DBGLOG(core, "DWARF Unit is a type unit: 0x{:x}", comp_unit->section_offset());
      type_units.push_back(comp_unit);
    }

    UnitReader reader{comp_unit};
    for (auto [die_index, die] : utils::EnumerateView(dies)) {
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

      std::string_view name;
      std::string_view mangled_name;
      auto addr_representable = false;
      auto is_decl = false;
      auto is_super_scope_var = false;
      auto has_loc = false;
      reader.seek_die(die);
      for (auto value : abb.attributes) {

        switch (value.name) {
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
        case Attribute::DW_AT_high_pc:
        case Attribute::DW_AT_ranges:
        case Attribute::DW_AT_entry_pc:
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
        default:
          reader.skip_attribute(value);
          break;
        }
      }

      switch (die.tag) {
      case DwarfTag::DW_TAG_variable:
        // We only register global variables, everything else wouldn't make sense.
        if (!name.empty() && has_loc && is_super_scope_var) {
          global_variables.push_back({name, die_index, comp_unit});
          if (!mangled_name.empty() && mangled_name != name) {
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
      case DwarfTag::DW_TAG_unspecified_type:
        if (!name.empty() && !is_decl) {
          types.push_back({name, die_index, comp_unit});
        }
        if (!mangled_name.empty() && !is_decl) {
          types.push_back({mangled_name, die_index, comp_unit});
        }
        break;
      case DwarfTag::DW_TAG_inlined_subroutine:
      case DwarfTag::DW_TAG_subprogram: {
        if (!addr_representable) {
          break;
        }

        const auto &[is_mem_fn, resolved_name] = IsMemberFunction(followed_references, *comp_unit, die);
        if (!name.empty() || resolved_name.has_value()) {
          if (is_mem_fn) {
            methods.push_back({resolved_name.value_or(name), die_index, comp_unit});
          } else {
            free_functions.push_back({resolved_name.value_or(name), die_index, comp_unit});
          }
        }

        if (!mangled_name.empty()) {
          if (is_mem_fn) {
            methods.push_back({mangled_name, die_index, comp_unit});
          } else {
            free_functions.push_back({mangled_name, die_index, comp_unit});
          }
        }
      } break;
      case DwarfTag::DW_TAG_namespace:
      case DwarfTag::DW_TAG_imported_declaration:
        if (!name.empty()) {
          namespaces.push_back({name, die_index, comp_unit});
        }
        break;
      default:
        continue;
      }
    }
  }
  auto idx = obj->GetNameIndex();
  idx->namespaces.merge(namespaces);
  idx->free_functions.merge(free_functions);
  idx->global_variables.merge(global_variables);
  idx->methods.merge(methods);
  idx->types.merge_types(obj, types);

  if (!initialized_cus.empty()) {
    obj->AddInitializedCompileUnits(initialized_cus);
  }

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
      src.set_address_boundary(lowest, highest);
    }
  } else if (version == DwarfVersion::D5) {
    ASSERT(elf->debug_rnglists != nullptr,
           "DWARF Version 5 requires DW_AT_ranges in a .debug_aranges but no such section has been found");
    if (ranges_offset.form == AttributeForm::DW_FORM_sec_offset) {
      auto addr_range = sym::dw::read_boundaries(elf->debug_rnglists, ranges_offset.unsigned_value());
      src.set_address_boundary(addr_range.start_pc(), addr_range.end_pc());
    } else {
      auto ranges =
        sym::dw::read_boundaries(*cu, ResolvedRangeListOffset::make(*cu, ranges_offset.unsigned_value()));
      AddrPtr lowpc = static_cast<u64>(-1);
      AddrPtr highpc = nullptr;
      for (const auto [low, high] : ranges) {
        lowpc = std::min(low, lowpc);
        highpc = std::max(high, highpc);
      }
      src.set_address_boundary(lowpc, highpc);
    }
  }
}

sym::CompilationUnit
IndexingTask::initialize_compilation_unit(UnitData *cu, const DieMetaData &cu_die) noexcept
{
  const auto &abbrs = cu->get_abbreviation(cu_die.abbreviation_code);
  UnitReader reader{cu};
  reader.seek_die(cu_die);
  sym::CompilationUnit new_cu{cu};

  std::optional<AddrPtr> low;
  std::optional<AddrPtr> high;

  for (const auto &abbr : abbrs.attributes) {
    switch (abbr.name) {
    case Attribute::DW_AT_stmt_list: {
      const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
      const auto offset = attr.address();
      new_cu.ProcessSourceCodeFiles(offset);
      break;
    }
    case Attribute::DW_AT_name: {
      const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
      const auto name = attr.string();
      new_cu.set_name(name);
      break;
    }
    case Attribute::DW_AT_ranges: {
      const auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
      process_cu_boundary(attr, new_cu);
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
  if (!new_cu.known_address_boundary() && boundary_seen) {
    new_cu.set_address_boundary(low.value(), low.value() + high.value());
  }

  return new_cu;
}

sym::PartialCompilationUnitSymbolInfo
IndexingTask::initialize_partial_compilation_unit(UnitData *partial_cu, const DieMetaData &) noexcept
{
  // TODO("IndexingTask::initialize_partial_compilation_unit not yet implemented");
  return sym::PartialCompilationUnitSymbolInfo{partial_cu};
}
}; // namespace sym::dw