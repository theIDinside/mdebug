#include "commands.h"
#include "../target.h"
#include "../tracer.h"

namespace cmd {
bool
Continue::execute(Tracer *tracer) const noexcept
{
  auto &target = tracer->get_target(thread_id);
  if (continue_all) {
    target.set_all_running(RunType::Continue);
  } else {
    target.get_task(thread_id)->set_running(RunType::Continue);
  }
  return true;
}
}; // namespace cmd