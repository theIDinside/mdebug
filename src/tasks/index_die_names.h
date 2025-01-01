#pragma once
#include "../symbolication/dwarf/die.h"
#include "../utils/worker_task.h"

class ObjectFile;

namespace sym {
class CompilationUnit;
class PartialCompilationUnitSymbolInfo;
} // namespace sym

namespace sym::dw {
struct DieMetaData;
class IndexingTask : public utils::Task
{
public:
  IndexingTask(ObjectFile *obj, std::span<UnitData *> cus_to_index) noexcept;
  virtual ~IndexingTask() = default;
  /* Takes `obj`, and retrieves `UnitData* for all cu's in the object file and does it's name+die indexing.*/
  static std::vector<IndexingTask *> CreateIndexingJobs(ObjectFile *obj, std::pmr::memory_resource* taskGroupAllocator);

protected:
  void execute_task(std::pmr::memory_resource* temporaryAllocator) noexcept override;
  /** Creates a sym::dw::CompilationUnit, which contains things like stamped out line number program entries, high
   * and low pc values for a CU, name of the file*/

private:
  // Initializes sym::dw::CompilationUnit objects with `ObjectFile` (`obj`), setting it's high/low PC boundary as
  // well as "stamps out" it's line number program entries (See source_file.h for `sym::dw::LineTable` and
  // `sym::dw::CompilationUnit`)
  sym::PartialCompilationUnitSymbolInfo initialize_partial_compilation_unit(UnitData *partial_cu,
                                                                            const DieMetaData &pcu_die) noexcept;
  ObjectFile *obj;
  std::vector<UnitData *> cus_to_index;
};
} // namespace sym::dw