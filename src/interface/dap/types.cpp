#include "types.h"

namespace ui::dap {

std::string
Breakpoint::serialize() const noexcept
{
  return fmt::format(R"({{"id": {}, "verified": {}, "instructionReference": "{}"}})", id, verified, addr);
}
}; // namespace ui::dap