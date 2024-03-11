#include "lnp.h"
#include <symbolication/dwarf/lnp.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/thread_pool.h>

namespace sym::dw {
LineNumberProgramTask::LineNumberProgramTask(ObjectFile *obj, std::span<LNPHeader> programs_to_parse) noexcept
    : obj(obj), lnp_headers(programs_to_parse)
{
}

/*static*/ std::vector<LineNumberProgramTask *>
LineNumberProgramTask::create_jobs_for(ObjectFile *obj)
{
  auto lnp_headers = obj->get_lnp_headers();
  std::vector<LineNumberProgramTask *> result;
  result.reserve(utils::ThreadPool::get_global_pool()->worker_count());
  auto work_sizes = utils::ThreadPool::calculate_job_sizes(lnp_headers);
  auto idx = 0;
  for (const auto work_size : work_sizes) {
    auto start = idx;
    result.push_back(new LineNumberProgramTask(obj, lnp_headers.subspan(start, work_size)));
    idx += work_size;
  }
  return result;
}

void
LineNumberProgramTask::execute_task() noexcept
{
  for (auto &header : lnp_headers) {
    sym::dw::compute_line_number_program(obj->get_plte(header.sec_offset), obj->elf, &header);
  }
}
} // namespace sym::dw