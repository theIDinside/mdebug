#pragma once
#include "../symbolication/dwarf/die.h"
#include "../utils/worker_task.h"

struct ObjectFile;

namespace sym::dw {
class IndexingTask : public utils::Task
{
public:
  IndexingTask(ObjectFile *obj, std::span<UnitData *> cus_to_index) noexcept;
  virtual ~IndexingTask() = default;
  /* Takes `obj`, and retrieves `UnitData* for all cu's in the object file and does it's name+die indexing.*/
  static std::vector<IndexingTask *> create_jobs_for(ObjectFile *obj);

protected:
  void execute_task() noexcept override;

private:
  ObjectFile *obj;
  std::span<UnitData *> cus_to_index;
};
} // namespace sym::dw