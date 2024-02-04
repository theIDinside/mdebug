#include "types.h"
#include <supervisor.h>

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

VariablesReference::VariablesReference(NonNullPtr<ObjectFile> obj, int ref, int thread, int frame_id, int parent,
                                       EntityType type) noexcept
    : id(ref), thread_id(thread), frame_id(frame_id), parent_(parent), type(type), scope_type(), object_file(obj)
{
}

VariablesReference::VariablesReference(NonNullPtr<ObjectFile> obj, int ref, int thread, int frame_id, int parent,
                                       EntityType type, ScopeType scope_type) noexcept
    : id(ref), thread_id(thread), frame_id(frame_id), parent_(parent), type(type), scope_type(scope_type),
      object_file(obj)
{
}

bool
VariablesReference::has_parent() const noexcept
{
  return 0 != *parent_;
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