#include "types.h"

namespace ui::dap {

std::string
Breakpoint::serialize() const noexcept
{
  if (source_path) {
    if (col && line) {
      return fmt::format(
          R"({{"id": {}, "verified": {}, "instructionReference": "{}", "line": {}, "column": {}, "source": {{ "name": "{}", "path": "{}" }} }})",
          id, verified, addr, *line, *col, *source_path, *source_path);
    } else {
      // only line
      return fmt::format(
          R"({{"id": {}, "verified": {}, "instructionReference": "{}", "line": {}, "source": {{ "name": "{}", "path": "{}" }} }})",
          id, verified, addr, *line, *source_path, *source_path);
    }
  } else {
    return fmt::format(R"({{"id": {}, "verified": {}, "instructionReference": "{}" }})", id, verified, addr);
  }
}
}; // namespace ui::dap