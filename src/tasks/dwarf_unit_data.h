#pragma once
#include <symbolication/dwarf/lnp.h>
#include <symbolication/dwarf/unit_header.h>
#include <utils/worker_task.h>

struct ObjectFile;

namespace sym::dw {

class UnitData;

class UnitDataTask : public utils::Task
{
public:
  UnitDataTask(ObjectFile *obj, std::vector<UnitHeader> &&headers) noexcept;
  ~UnitDataTask() override = default;
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

/// In some cases we may load dies into memory. When we want to decrement reference count, we don't want to do so
/// on the main thread.
// We want to:
// - load it into memory
// - process it in the fashion we require
// - return the result to the caller of the function processing the DIEs
// - but right before we do, post to the thread pool the task that handles ref count decrement and *possible* DIE
// metadata clean up (if refcount -> 0. Either way, it's unnecessary work on the main thread.)
class UnitRefCountDrop : public utils::Task
{
  std::vector<sym::dw::UnitData *> compilation_units{};

public:
  UnitRefCountDrop(std::vector<sym::dw::UnitData *> &&cus) noexcept;
  ~UnitRefCountDrop() noexcept override = default;
  void execute_task() noexcept final;
};
} // namespace sym::dw