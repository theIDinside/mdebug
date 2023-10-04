#pragma once
#include "die.h"
#include "symbol/dwarf/dwarf_defs.h"
#include "symbol/dwarf2/unit.h"
#include <common.h>
#include <map>
#include <unordered_set>
#include <utils/worker_task.h>

namespace sym {
struct ObjectFile;
};

namespace sym::dw2 {

class DwarfUnitData;

struct NameOffsetPair
{
  std::string_view name;
  u64 die_reference;
};

struct NameSets
{
  std::multimap<std::string_view, DieKey> free_functions{};
  std::multimap<std::string_view, DieKey> methods{};
  std::multimap<std::string_view, DieKey> types{};
  std::multimap<std::string_view, DieKey> global_vars{};
  std::multimap<std::string_view, DieKey> namespaces{};

  u64 name_count() const noexcept;
};

// An index between names -> DIE in .debug_info or .debug_types for an Object file
class NameIndex
{
public:
  NameIndex() noexcept = default;
  // Spawns _all_ the work for indexing names.
  void index_names() noexcept;
  void add_processed_cu(const NameSets &indexed_cu_names) noexcept;
  void set_objfile(ObjectFile *obj) noexcept;

private:
  ObjectFile *p_obj = nullptr;
  // Names. Since they're sorted in order, looking for values that might be keyed by duplicate keys
  // this is fine, since this container is ordered, thus, search will always "find first" (at which point we can
  // iterate forwards from)
  std::multimap<std::string_view, DieKey> free_functions{};
  std::multimap<std::string_view, DieKey> methods{};
  std::multimap<std::string_view, DieKey> types{};
  std::multimap<std::string_view, DieKey> global_vars{};
  std::multimap<std::string_view, DieKey> namespaces{};
  // Non-unique names
  std::vector<std::vector<DieKey>> non_unique_names;
  SpinLock lock{};
};

class IndexingTask : public utils::Task
{
public:
  using Work = std::span<DwarfUnitData *>;
  IndexingTask(ObjectFile *obj, std::span<DwarfUnitData *> cus) noexcept;
  virtual ~IndexingTask();
  void execute_task() noexcept override;
  static std::vector<IndexingTask *> create_work(ObjectFile *obj, Work work) noexcept;

private:
  std::span<DwarfUnitData *> cus;
  ObjectFile *p_obj;
};

} // namespace sym::dw2