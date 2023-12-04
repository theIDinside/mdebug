#pragma once
#include "../symbolication/dwarf/die.h"
#include "../utils/worker_task.h"

struct ObjectFile;

namespace sym::dw {
class UnitDataTask : public utils::Task
{
public:
  UnitDataTask(ObjectFile *obj, std::vector<UnitHeader> &&headers) noexcept;
  virtual ~UnitDataTask() = default;
  /* Takes `obj`, parses it's CU Headers and divides all CU's over `size of thread pool`.*/
  static std::vector<UnitDataTask *> create_jobs_for(ObjectFile *obj);

protected:
  void execute_task() noexcept override;

private:
  ObjectFile *obj;
  std::vector<UnitHeader> cus_to_parse;
};
} // namespace sym::dw