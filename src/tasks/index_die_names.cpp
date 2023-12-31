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
#include "symbolication/dwarf/rnglists.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_defs.h"
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
  const auto cus = std::span{obj->compilation_units()};
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

void
IndexingTask::execute_task() noexcept
{
  using NameSet = std::vector<NameIndex::NameDieTuple>;
  NameSet free_functions;
  NameSet methods;
  NameSet types;
  NameSet global_variables;
  NameSet namespaces;

  std::vector<sym::SourceFileSymbolInfo> initialized_cus{};

  ScopedDefer clear_metadata{[&]() {
    for (auto &comp_unit : cus_to_index) {
      comp_unit->clear_die_metadata();
    }
  }};

  for (auto comp_unit : cus_to_index) {
    std::vector<i64> implicit_consts;
    const auto &dies = comp_unit->get_dies();
    if (dies.front().tag == DwarfTag::DW_TAG_compile_unit) {
      sym::SourceFileSymbolInfo new_cu_file = initialize_compilation_unit(comp_unit, dies.front());
      initialized_cus.push_back(std::move(new_cu_file));
    } else if (dies.front().tag == DwarfTag::DW_TAG_partial_unit) {
      sym::PartialCompilationUnitSymbolInfo partial_cu_file =
          initialize_partial_compilation_unit(comp_unit, dies.front());
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

      // const auto resolved_attributes = unit_data->get_resolved_attributes(die.abbrev_code);

      const auto &abb = comp_unit->get_abbreviation(die.abbreviation_code);
      std::string_view name;
      std::string_view mangled_name;
      auto addr_representable = false;
      auto is_decl = false;
      auto is_super_scope_var = false;
      auto has_loc = false;
      reader.seek_die(die);
      for (auto value : abb.attributes) {
        auto attr = read_attribute_value(reader, value, abb.implicit_consts);
        switch (value.name) {
        // register name
        case Attribute::DW_AT_name:
          name = attr.string();
          break;
        case Attribute::DW_AT_linkage_name:
          mangled_name = attr.string();
          break;
        // is address-representable?
        case Attribute::DW_AT_low_pc:
        case Attribute::DW_AT_high_pc:
        case Attribute::DW_AT_ranges:
        case Attribute::DW_AT_entry_pc:
          addr_representable = true;
          break;
        // is global or static value?
        case Attribute::DW_AT_location:
        case Attribute::DW_AT_const_value:
          has_loc = true;
          is_super_scope_var = die.is_super_scope_variable();
          break;
        case Attribute::DW_AT_declaration:
          is_decl = true;
          break;
        default:
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
        if (!name.empty() && !is_decl)
          // names.types.insert({name, DieKey{die.sec_offset}});
          types.push_back({name, die_index, comp_unit});
        if (!mangled_name.empty() && !is_decl)
          // names.types.insert({mangled_name, DieKey{die.sec_offset}});
          types.push_back({mangled_name, die_index, comp_unit});
        break;
      case DwarfTag::DW_TAG_inlined_subroutine:
      case DwarfTag::DW_TAG_subprogram: {
        if (!addr_representable)
          break;
        const bool is_mem_fn = false;
        // = DIEReference(comp_unit, &die).is_member_fn();
        if (!name.empty()) {
          if (is_mem_fn) {
            methods.push_back({name, die_index, comp_unit});
            // names.methods.insert(std::make_pair(name, DieKey{die.sec_offset}));
          } else {
            free_functions.push_back({name, die_index, comp_unit});
            // names.free_functions.insert(std::make_pair(name, DieKey{die.sec_offset}));
          }
        }

        if (!mangled_name.empty()) {
          if (is_mem_fn) {
            methods.push_back({mangled_name, die_index, comp_unit});
            // names.methods.insert(std::make_pair(name, DieKey{die.sec_offset}));
          } else {
            free_functions.push_back({mangled_name, die_index, comp_unit});
            // names.free_functions.insert(std::make_pair(name, DieKey{die.sec_offset}));
          }
        }
      } break;
      case DwarfTag::DW_TAG_namespace:
      case DwarfTag::DW_TAG_imported_declaration:
        if (!name.empty())
          // names.namespaces.insert({name, DieKey{die.sec_offset}});
          namespaces.push_back({name, die_index, comp_unit});
        break;
      default:
        continue;
      }
    }
  }
  auto idx = obj->name_index();
  idx->namespaces.merge(namespaces);
  idx->free_functions.merge(free_functions);
  idx->global_variables.merge(global_variables);
  idx->methods.merge(methods);
  idx->types.merge(types);

  if (!initialized_cus.empty())
    obj->add_initialized_cus(initialized_cus);
}

static void
process_cu_boundary(u64 ranges_offset, sym::SourceFileSymbolInfo &src) noexcept
{
  auto cu = src.get_dwarf_unit();
  const auto version = cu->header().version();
  ASSERT(version == DwarfVersion::D4 || version == DwarfVersion::D5, "Dwarf version not supported");
  auto elf = cu->get_objfile()->parsed_elf;
  if (version == DwarfVersion::D4) {
    auto byte_ptr = reinterpret_cast<const u64 *>(elf->debug_ranges->offset(ranges_offset));
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
        if (end == 0)
          break;
        else
          continue;
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
    ASSERT(elf->debug_aranges != nullptr,
           "DWARF Version 5 requires DW_AT_ranges in a .debug_aranges but no such section has been found");
    auto addr_range = sym::dw::read_boundaries(elf->debug_rnglists, ranges_offset);
    src.set_address_boundary(addr_range.start_pc(), addr_range.end_pc());
  }
}

sym::SourceFileSymbolInfo
IndexingTask::initialize_compilation_unit(UnitData *cu, const DieMetaData &cu_die) noexcept
{
  const auto &abbrs = cu->get_abbreviation(cu_die.abbreviation_code);
  UnitReader reader{cu};
  reader.seek_die(cu_die);
  sym::SourceFileSymbolInfo new_cu{cu};

  std::optional<AddrPtr> low;
  std::optional<AddrPtr> high;

  for (const auto &abbr : abbrs.attributes) {
    auto attr = read_attribute_value(reader, abbr, abbrs.implicit_consts);
    switch (attr.name) {
    case Attribute::DW_AT_stmt_list: {
      const auto offset = attr.address();
      new_cu.set_linetable(offset);
      break;
    }
    case Attribute::DW_AT_name: {
      auto name = attr.string();
      new_cu.set_name(name);
      break;
    }
    case Attribute::DW_AT_ranges: {
      process_cu_boundary(attr.address(), new_cu);
    } break;
    case Attribute::DW_AT_low_pc: {
      if (!low)
        low = attr.address();
    } break;
    case Attribute::DW_AT_high_pc: {
      high = attr.address();
    } break;
    case Attribute::DW_AT_import:
      break;
    default:
      continue;
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