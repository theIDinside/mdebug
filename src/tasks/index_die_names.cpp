#include "index_die_names.h"
#include "../symbolication/dwarf.h"
#include "../symbolication/dwarf/debug_info_reader.h"
#include "../symbolication/dwarf/name_index.h"
#include "../symbolication/elf.h"
#include "../symbolication/objfile.h"
#include "../utils/enumerator.h"
#include "../utils/thread_pool.h"

namespace sym::dw {

static AttributeValue
read_attribute_value(UnitReader &reader, Abbreviation abbr, std::vector<i64> &implicit_consts) noexcept
{
  static constexpr auto IS_DWZ = false;
  ASSERT(IS_DWZ == false, ".dwo files not supported yet");
  if (abbr.IMPLICIT_CONST_INDEX != UINT8_MAX) {
    return AttributeValue{implicit_consts[abbr.IMPLICIT_CONST_INDEX], AttributeForm::DW_FORM_implicit_const,
                          abbr.name};
  }

  const auto elf = reader.elf();

  switch (abbr.form) {
  case AttributeForm::DW_FORM_ref_addr:
    return AttributeValue{reader.read_offset(), abbr.form, abbr.name};
    break;
  case AttributeForm::DW_FORM_addr: {
    return AttributeValue{reader.read_address(), abbr.form, abbr.name};
  }
  case AttributeForm::Reserved:
    PANIC("Can't handle RESERVED");
  case AttributeForm::DW_FORM_block2:
    return AttributeValue{reader.read_block(2), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_block4:
    return AttributeValue{reader.read_block(4), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data2:
    return AttributeValue{reader.read_integral<u16>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data4:
    return AttributeValue{reader.read_integral<u32>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data8:
    return AttributeValue{reader.read_integral<u64>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_data16:
    return AttributeValue{reader.read_block(16), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_string:
    return AttributeValue{reader.read_string(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_exprloc:
    [[fallthrough]];
  case AttributeForm::DW_FORM_block: {
    const auto size = reader.uleb128();
    return AttributeValue{reader.read_block(size), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_block1: {
    const auto size = reader.read_integral<u8>();
    return AttributeValue{reader.read_block(size), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_data1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_flag:
    return AttributeValue{reader.read_integral<u8>(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_sdata:
    return AttributeValue{reader.leb128(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_strp: {
    ASSERT(elf->debug_str != nullptr, ".debug_str expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.read_offset();
      std::string_view indirect_str{(const char *)elf->debug_str->begin() + offset};
      return AttributeValue{indirect_str, abbr.form, abbr.name};
    }
  }
  case AttributeForm::DW_FORM_line_strp: {
    ASSERT(elf->debug_line_str != nullptr, ".debug_line expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.read_offset();
      const auto ptr = elf->debug_line_str->begin() + offset;
      const std::string_view indirect_str{(const char *)ptr};
      return AttributeValue{indirect_str, abbr.form, abbr.name};
    }
  }
  case AttributeForm::DW_FORM_udata:
    return AttributeValue{reader.uleb128(), abbr.form, abbr.name};
  case AttributeForm::DW_FORM_ref1: {
    const auto offset = reader.read_integral<u8>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref2: {
    const auto offset = reader.read_integral<u16>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref4: {
    const auto offset = reader.read_integral<u32>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref8: {
    const auto offset = reader.read_integral<u64>();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_udata: {
    const auto offset = reader.uleb128();
    return AttributeValue{reader.read_section_offset(offset), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_indirect: {
    const auto new_form = (AttributeForm)reader.uleb128();
    Abbreviation new_abbr{.name = abbr.name, .form = new_form, .IMPLICIT_CONST_INDEX = UINT8_MAX};
    if (new_form == AttributeForm::DW_FORM_implicit_const) {
      const auto value = reader.leb128();
      new_abbr.IMPLICIT_CONST_INDEX = implicit_consts.size();
      implicit_consts.push_back(value);
    }
    return read_attribute_value(reader, new_abbr, implicit_consts);
  }
  case AttributeForm::DW_FORM_sec_offset: {
    const auto offset = reader.read_offset();
    return AttributeValue{offset, abbr.form, abbr.name};
  }

  case AttributeForm::DW_FORM_flag_present:
    return AttributeValue{(u64) true, abbr.form, abbr.name};
  // fall through. Nasty attribute forms; beware
  case AttributeForm::DW_FORM_strx1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx2:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx3:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx4: {
    const auto base = std::to_underlying(AttributeForm::DW_FORM_strx1) - 1;
    const auto bytes_to_read = std::to_underlying(abbr.form) - base;
    const auto idx = reader.read_n_bytes(bytes_to_read);
    return AttributeValue{reader.read_by_idx_from_str_table(idx, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_strx: {
    const auto idx = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_str_table(idx, {}), abbr.form, abbr.name};
  }

  // fall through. Nasty attribute forms; beware
  case AttributeForm::DW_FORM_addrx1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx2:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx3:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx4: {
    ASSERT(elf->debug_addr != nullptr, ".debug_addr not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto base = std::to_underlying(AttributeForm::DW_FORM_addrx1) - 1;
    const auto bytes_to_read = std::to_underlying(abbr.form) - base;
    const auto addr_index = reader.read_n_bytes(bytes_to_read);
    return AttributeValue{reader.read_by_idx_from_addr_table(addr_index, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_addrx: {
    ASSERT(elf->debug_addr != nullptr, ".debug_addr not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto addr_table_index = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_addr_table(addr_table_index, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_sup4:
    PANIC("Unsupported attribute form DW_FORM_ref_sup4");
  case AttributeForm::DW_FORM_strp_sup:
    PANIC("Unsupported attribute form DW_FORM_strp_sup");
  case AttributeForm::DW_FORM_ref_sig8:
    PANIC("Unsupported attribute form DW_FORM_ref_sig8");
  case AttributeForm::DW_FORM_implicit_const:
    ASSERT(abbr.IMPLICIT_CONST_INDEX != UINT8_MAX, "Invalid implicit const index");
    return AttributeValue{implicit_consts[abbr.IMPLICIT_CONST_INDEX], abbr.form, abbr.name};
  case AttributeForm::DW_FORM_loclistx: {
    ASSERT(elf->debug_loclist != nullptr, ".debug_rnglists not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto idx = reader.uleb128();
    return AttributeValue{reader.read_loclist_index(idx, {}), abbr.form, abbr.name};
  }

  case AttributeForm::DW_FORM_rnglistx: {
    ASSERT(elf->debug_rnglists != nullptr, ".debug_rnglists not read in or found in objfile {}",
           reader.objfile()->path.c_str());
    const auto addr_table_index = reader.uleb128();
    return AttributeValue{reader.read_by_idx_from_rnglist(addr_table_index, {}), abbr.form, abbr.name};
  }
  case AttributeForm::DW_FORM_ref_sup8:
    PANIC("Unsupported attribute form DW_FORM_ref_sup8");
    break;
  }
  PANIC("Unknown Attribute Form");
}

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

  for (auto comp_unit : cus_to_index) {
    comp_unit->load_dies();
    std::vector<i64> implicit_consts;
    const auto &dies = comp_unit->get_dies();
    if (dies.front().tag == DwarfTag::DW_TAG_compile_unit) {
      initialize_compilation_unit(comp_unit, dies.front());
    } else if (dies.front().tag == DwarfTag::DW_TAG_partial_unit) {
      initialize_partial_compilation_unit(comp_unit, dies.front());
    }

    UnitReader reader{comp_unit};
    for (const auto &[die_index, die] : utils::EnumerateView(dies)) {
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
      for (const auto value : abb.attributes) {
        auto attr = read_attribute_value(reader, value, implicit_consts);
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
}

void
IndexingTask::initialize_compilation_unit(UnitData *cu, const DieMetaData &cu_die) noexcept
{
  // TODO("IndexingTask::initialize_compilation_unit not yet implemented");
}
void
IndexingTask::initialize_partial_compilation_unit(UnitData *partial_cu, const DieMetaData &pcu_die) noexcept
{
  // TODO("IndexingTask::initialize_partial_compilation_unit not yet implemented");
}

}; // namespace sym::dw