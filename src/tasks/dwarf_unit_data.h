/** LICENSE TEMPLATE */
#pragma once
#include <memory_resource>
#include <symbolication/dwarf/lnp.h>
#include <symbolication/dwarf/unit_header.h>
#include <utils/worker_task.h>

namespace mdb {
class ObjectFile;
}
namespace mdb::sym::dw {

class UnitData;

class UnitDataTask : public mdb::Task
{
public:
  UnitDataTask(ObjectFile *obj, std::span<UnitHeader> headers) noexcept;
  ~UnitDataTask() override = default;
  /* Takes `obj`, parses it's CU Headers and divides all CU's over `size of thread pool`.*/
  static std::vector<UnitDataTask *> CreateParsingJobs(ObjectFile *obj,
                                                       std::pmr::memory_resource *allocator) noexcept;

protected:
  void ExecuteTask(std::pmr::memory_resource *temporaryAllocator) noexcept override;

private:
  ObjectFile *obj;
  std::vector<UnitHeader> mCompilationUnitsToParse;
};

} // namespace mdb::sym::dw