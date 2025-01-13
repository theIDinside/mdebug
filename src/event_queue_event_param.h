/** LICENSE TEMPLATE */
#pragma once
#include <optional>
#include <typedefs.h>

struct EventDataParam
{
  Pid target;
  std::optional<int> tid;
  std::optional<int> sig_or_code;
};