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

Breakpoint
Breakpoint::from_user_bp(std::shared_ptr<UserBreakpoint> user_bp) noexcept
{
  if (const auto addr = user_bp->address(); addr) {
    return Breakpoint{.id = user_bp->id,
                      .verified = true,
                      .addr = addr.value(),
                      .line = user_bp->line(),
                      .col = user_bp->column(),
                      .source_path = user_bp->source_file(),
                      .error_message = {}};
  } else {
    return Breakpoint{.id = user_bp->id,
                      .verified = false,
                      .addr = nullptr,
                      .line = {},
                      .col = {},
                      .source_path = {},
                      .error_message = "Address not in resident memory of tracee"};
  }
}

VariablesReference::VariablesReference(NonNullPtr<SymbolFile> obj, int ref, int thread, int frame_id, int parent,
                                       EntityType type) noexcept
    : id(ref), thread_id(thread), frame_id(frame_id), parent_(parent), type(type), scope_type(), object_file(obj)
{
}

VariablesReference::VariablesReference(NonNullPtr<SymbolFile> obj, int ref, int thread, int frame_id, int parent,
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