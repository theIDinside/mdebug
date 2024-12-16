#pragma once
#include <symbolication/dwarf/lnp.h>
#include <utils/worker_task.h>

class ObjectFile;

namespace sym::dw {

class LineNumberProgramTask : public utils::Task
{
public:
  LineNumberProgramTask(ObjectFile *obj, std::span<LNPHeader> programs_to_parse) noexcept;
  virtual ~LineNumberProgramTask() = default;
  static std::vector<LineNumberProgramTask *> create_jobs_for(ObjectFile *obj);

protected:
  void execute_task() noexcept override;

private:
  ObjectFile *obj;
  std::span<LNPHeader> lnp_headers;
};
} // namespace sym::dw
