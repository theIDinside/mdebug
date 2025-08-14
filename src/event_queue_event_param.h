/** LICENSE TEMPLATE */
#pragma once
#include <common/typedefs.h>
#include <optional>

namespace mdb {

struct EventDataParam
{
  SessionId target;
  std::optional<int> tid;
  std::optional<int> sig_or_code;
  std::optional<int> event_time;
};
} // namespace mdb