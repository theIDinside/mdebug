#include "dwarf_unit_data.h"
#include "symbolication/dwarf/die.h"
#include <symbolication/objfile.h>
#include <utils/thread_pool.h>
namespace sym::dw {

UnitDataTask::UnitDataTask(ObjectFile *obj, std::vector<UnitHeader> &&headers) noexcept
    : obj(obj), cus_to_parse(std::move(headers)), lnp_headers()
{
}

void
UnitDataTask::execute_task() noexcept
{
  std::vector<UnitData *> result;
  for (const auto &header : cus_to_parse) {
    auto unit_data = prepare_unit_data(obj, header);
    result.push_back(unit_data);
  }
  obj->set_unit_data(result);
}

void
UnitDataTask::set_lnp_headers(std::span<LNPHeader::shr_ptr> headers) noexcept
{
  lnp_headers = headers;
}

/*static*/
std::vector<UnitDataTask *>
UnitDataTask::create_jobs_for(ObjectFile *obj)
{
  auto headers = read_unit_headers(obj);
  std::vector<UnitDataTask *> result;
  result.reserve(utils::ThreadPool::get_global_pool()->worker_count());
  auto work_sizes = utils::ThreadPool::calculate_job_sizes(headers);
  auto idx = 0;
  for (const auto work_size : work_sizes) {
    auto start = idx;
    auto end = idx + work_size;
    result.push_back(new UnitDataTask{obj, {headers.begin() + start, headers.begin() + end}});
    idx += work_size;
  }
  return result;
}

} // namespace sym::dw