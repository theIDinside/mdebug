/** LICENSE TEMPLATE */
#pragma once
#include <optional>
#include <typedefs.h>

namespace mdb {

struct EventDataParam
{
  Pid target;
  std::optional<int> tid;
  std::optional<int> sig_or_code;
};
} // namespace mdb