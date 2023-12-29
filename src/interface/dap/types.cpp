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

/*static*/
Breakpoint
Breakpoint::non_verified(u32 id, std::string_view msg) noexcept
{
  return Breakpoint{.id = id,
                    .verified = false,
                    .addr = nullptr,
                    .line = {},
                    .col = {},
                    .source_path = {},
                    .error_message = msg};
}

bool
VariablesReference::has_parent() const noexcept
{
  return parent_ != 0;
}

std::optional<int>
VariablesReference::parent() const noexcept
{
  if (has_parent())
    return parent_;
  else
    return std::nullopt;
}

}; // namespace ui::dap