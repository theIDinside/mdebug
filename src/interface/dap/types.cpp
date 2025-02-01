/** LICENSE TEMPLATE */
#include "types.h"
#include <iterator>
#include <memory_resource>
#include <supervisor.h>
#include <symbolication/value.h>

namespace mdb::ui::dap {

std::pmr::string
Breakpoint::serialize(std::pmr::memory_resource *memoryResource) const noexcept
{
  std::pmr::string buf{memoryResource};
  // TODO(simon): Here we really should be using some form of arena allocation for the DAP interpreter
  // communication
  //  so that all these allocations can be "blinked" out of existence, i.e. all serialized command results, will be
  //  manually de/allocated by us. But that's the future.
  buf.reserve(256);
  auto it = std::back_inserter(buf);
  it = fmt::format_to(it, R"({{"id":{},"verified":{})", id, verified);
  if (verified) {
    it = fmt::format_to(it, R"(,"instructionReference": "{}")", addr);
  } else {
    it = fmt::format_to(it, R"(,"message": "{}")", error_message.value());
  }

  if (line) {
    it = fmt::format_to(it, R"(,"line": {})", *line);
  }

  if (col) {
    it = fmt::format_to(it, R"(,"column": {})", *col);
  }
  if (source_path) {
    it = fmt::format_to(it, R"(,"source": {{ "name": "{}", "path": "{}" }})", *source_path, *source_path);
  }
  it = fmt::format_to(it, R"(}})");
  return buf;
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
                    .error_message = std::string{msg}};
}

Breakpoint
Breakpoint::from_user_bp(const UserBreakpoint &user_bp) noexcept
{
  if (const auto addr = user_bp.Address(); addr) {
    return Breakpoint{.id = user_bp.mId,
                      .verified = true,
                      .addr = addr.value(),
                      .line = user_bp.Line(),
                      .col = user_bp.Column(),
                      .source_path = user_bp.GetSourceFile(),
                      .error_message = {}};
  } else {
    return Breakpoint{.id = user_bp.mId,
                      .verified = false,
                      .addr = nullptr,
                      .line = {},
                      .col = {},
                      .source_path = {},
                      .error_message = user_bp.GetErrorMessage()};
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
  if (has_parent()) {
    return parent_;
  } else {
    return std::nullopt;
  }
}
}; // namespace mdb::ui::dap