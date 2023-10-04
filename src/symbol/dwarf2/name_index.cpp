#include "name_index.h"
#include "../objfile.h"
#include "symbol/dwarf2/die.h"
#include "unit.h"
#include "utils/worker_task.h"
#include <utils/thread_pool.h>

namespace sym::dw2 {

enum class Scope : u8
{
  Local = 0,
  Static,
  Global
};

u64
NameSets::name_count() const noexcept
{
  return free_functions.size() + methods.size() + types.size() + global_vars.size() + namespaces.size();
}

void
NameIndex::index_names() noexcept
{
  ASSERT(p_obj != nullptr, "Initialization of name index failed: no objfile");
  auto &compile_units = p_obj->get_cus();
  const auto counts = utils::ThreadPool::work_sizes(compile_units, 10);
  std::span span{compile_units};
  auto offset = 0;
  utils::TaskGroup tg{"Index names"};
  for (const auto sz : counts) {
    tg.add_task(new IndexingTask(p_obj, span.subspan(offset, sz)));
    offset += sz;
  }
  tg.schedule_tasks().wait();
}

void
NameIndex::set_objfile(ObjectFile *objfile) noexcept
{
  p_obj = objfile;
}

void
NameIndex::add_processed_cu(const NameSets &indexed_cu_names) noexcept
{
  LockGuard guard(lock);
  for (const auto &[n, k] : indexed_cu_names.free_functions) {
    DLOG("mdb", "free_functions {}, die=0x{:x}", n, k.sec_offset);
    free_functions.insert({n, k});
  }
  for (const auto &[n, k] : indexed_cu_names.methods) {
    DLOG("mdb", "member functions: {}, die=0x{:x}", n, k.sec_offset);
    methods.insert({n, k});
  }
  for (const auto &[n, k] : indexed_cu_names.types) {
    DLOG("mdb", "types: {}, die=0x{:x}", n, k.sec_offset);
    types.insert({n, k});
  }
  for (const auto &[n, k] : indexed_cu_names.global_vars) {
    DLOG("mdb", "globals: {}, die=0x{:x}", n, k.sec_offset);
    global_vars.insert({n, k});
  }
  for (const auto &[n, k] : indexed_cu_names.namespaces) {
    DLOG("mdb", "namespaces: {}, die=0x{:x}", n, k.sec_offset);
    namespaces.insert({n, k});
  }
  DLOG("mdb", "Added {} names", indexed_cu_names.name_count());
}

IndexingTask::IndexingTask(ObjectFile *obj, std::span<DwarfUnitData *> cu_work) noexcept
    : utils::Task(), cus(cu_work), p_obj(obj)
{
}

IndexingTask::~IndexingTask() {}

void
IndexingTask::execute_task() noexcept
{
  NameSets names;
  for (auto &unit_data : cus) {
    UnitReader reader{unit_data};
    unit_data->load_dies();
    std::vector<i64> implicit_consts{};
    for (const auto &die : unit_data->dies()) {
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

      const auto resolved_attributes = unit_data->get_resolved_attributes(die.abbrev_code);
      const auto &abb = unit_data->get_abbreviation_set(die.abbrev_code);
      std::string_view name;
      std::string_view mangled_name;
      auto addr_representable = false;
      auto is_decl = false;
      auto is_super_scope_var = false;
      auto has_loc = false;
      reader.set_die(die);
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
          is_super_scope_var = is_super_scope_variable(die);
          break;
        case Attribute::DW_AT_declaration:
          is_decl = true;
          break;
        }
      }

      switch (die.tag) {
      case DwarfTag::DW_TAG_variable:
        // We only register global variables, everything else wouldn't make sense.
        if (!name.empty() && has_loc && is_super_scope_var) {
          names.global_vars.insert(std::make_pair(name, DieKey{die.sec_offset}));
          if (!mangled_name.empty() && mangled_name != name) {
            names.global_vars.insert(std::make_pair(mangled_name, DieKey{die.sec_offset}));
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
          names.types.insert({name, DieKey{die.sec_offset}});
        if (!mangled_name.empty() && !is_decl)
          names.types.insert({mangled_name, DieKey{die.sec_offset}});
        break;
      case DwarfTag::DW_TAG_inlined_subroutine:
      case DwarfTag::DW_TAG_subprogram: {
        if (!addr_representable)
          break;
        const bool is_mem_fn = DIEReference(unit_data, &die).is_member_fn();
        if (!name.empty()) {
          if (is_mem_fn) {
            names.methods.insert(std::make_pair(name, DieKey{die.sec_offset}));
          } else {
            names.free_functions.insert(std::make_pair(name, DieKey{die.sec_offset}));
          }
        }
        // Do we even need to record this? Because, why?
        // if (!mangled_name.empty()) {}
      } break;
      case DwarfTag::DW_TAG_namespace:
      case DwarfTag::DW_TAG_imported_declaration:
        if (!name.empty())
          names.namespaces.insert({name, DieKey{die.sec_offset}});
        break;
      default:
        continue;
      }
    }
  }
  p_obj->get_name_index().add_processed_cu(names);
}

/*static*/
std::vector<IndexingTask *>
IndexingTask::create_work(ObjectFile *obj, Work work) noexcept
{
  const auto work_sizes = utils::ThreadPool::work_sizes(work, 10);
  auto offset = 0;
  std::vector<IndexingTask *> result;
  for (const auto sz : work_sizes) {
    result.push_back(new IndexingTask(obj, work.subspan(offset, sz)));
    offset += sz;
  }
  return result;
}

} // namespace sym::dw2