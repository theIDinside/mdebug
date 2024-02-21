#pragma once
#include <symbolication/dwarf/lnp.h>
#include <symbolication/dwarf/unit_header.h>
#include <utils/worker_task.h>

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
  void set_lnp_headers(std::span<LNPHeader::shr_ptr> lnp_headers) noexcept;

private:
  ObjectFile *obj;
  std::vector<UnitHeader> cus_to_parse;
  std::span<LNPHeader::shr_ptr> lnp_headers;
};
} // namespace sym::dw