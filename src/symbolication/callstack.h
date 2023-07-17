#pragma once
#include "../common.h"
#include <vector>

namespace sym {
struct Frame
{
  int level;
  TPtr<void> start, end;
  std::optional<std::string_view> fn_name;
};

struct CallStack
{
  std::vector<Frame> frames;
};
} // namespace sym