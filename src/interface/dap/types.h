/** LICENSE TEMPLATE */
#pragma once
#include "tracee_pointer.h"
#include "utils/immutable.h"
#include "utils/macros.h"
#include <fmt/format.h>
#include <memory_resource>
#include <string_view>
#include <typedefs.h>

class SymbolFile;
class UserBreakpoint;

namespace sym {
class Value;
}

namespace ui::dap {

struct Source
{
  std::string_view name;
  std::string_view path;
};

// comments describe the name of the field in the protocl
struct Breakpoint
{
  // id
  u32 id;
  // verified
  bool verified;
  // instructionReference
  AddrPtr addr;

  std::optional<u32> line;
  std::optional<u32> col;
  std::optional<std::string_view> source_path;
  std::optional<std::string> error_message;

  std::pmr::string serialize(std::pmr::memory_resource* memoryResource) const noexcept;
  static Breakpoint non_verified(u32 id, std::string_view msg) noexcept;
  static Breakpoint from_user_bp(const UserBreakpoint& user_bp) noexcept;
};

struct DataBreakpoint
{
  std::string data_id;
  std::string_view access_type;
  std::string condition;
  std::string hit_condition;
};

struct Thread
{
  int id;
  std::string_view name;
};

struct StackFrame
{
  int id;
  std::string_view name;
  std::optional<Source> source;
  int line;
  int column;
  std::string rip;
};

struct StackTraceFormat
{
  bool parameters : 1;
  bool parameterTypes : 1;
  bool parameterNames : 1;
  bool parameterValues : 1;
  bool line : 1;
  bool module : 1;
  bool includeAll : 1;
};

enum class ScopeType : u8
{
  Arguments = 0,
  Locals,
  Registers
};

struct Scope
{
  ScopeType type{};
  u32 variables_reference{};

  constexpr std::string_view
  name() const noexcept
  {
    switch (type) {
    case ScopeType::Arguments:
      return "Arguments";
    case ScopeType::Locals:
      return "Locals";
    case ScopeType::Registers:
      return "Registers";
    default:
      PANIC("Unhandled scope type");
    }
    MIDAS_UNREACHABLE
  }

  constexpr std::string_view
  presentation_hint() const noexcept
  {
    switch (type) {
    case ScopeType::Arguments:
      return "arguments";
    case ScopeType::Locals:
      return "locals";
    case ScopeType::Registers:
      return "registers";
    default:
      PANIC("Unhandled presentation hint to-string");
    }
    MIDAS_UNREACHABLE
  }
};

enum class EntityType
{
  Scope,
  Frame,
  Variable
};

class VariablesReference
{
public:
  VariablesReference(NonNullPtr<SymbolFile> obj, int ref, int thread, int frame_id, int parent,
                     EntityType type) noexcept;
  VariablesReference(NonNullPtr<SymbolFile> obj, int ref, int thread, int frame_id, int parent, EntityType type,
                     ScopeType scopeType) noexcept;
  VariablesReference &operator=(const VariablesReference &) = default;
  VariablesReference &operator=(VariablesReference &&) = default;
  VariablesReference(VariablesReference &&) = default;
  VariablesReference(const VariablesReference &) = default;

  bool has_parent() const noexcept;
  std::optional<int> parent() const noexcept;

  // actual variablesReference value
  Immutable<int> id;
  // The execution context (Task) that this variable reference exists in
  Immutable<int> thread_id;
  // The frame id this variable reference exists in
  Immutable<int> frame_id;
  // (Possible) parent reference. A scope has a frame as it's parent. A variable has a scope or another variable as
  // it's parent. To walk up the hierarchy, one would read the variables reference map using the parent key
  Immutable<int> parent_;
  // The reference type
  Immutable<EntityType> type;
  // TODO(simon): INCREDIBLE HACK. We should refactor VariablesReferences. See "our own" implementation in Midas
  // (though written in Python). That is a better solution than having to carry this extra field for a WHOLE BUNCH
  // of variables references that aren't of "scope type"
  Immutable<std::optional<ScopeType>> scope_type;

  // The "symbol context" for this variable reference.
  // Keep it a NonNullPtr<ObjectFile> instead of a reference, because we want pointer comparison for equality /
  // identify. Because only 1 objectfile of some binary will *ever* be loaded into memory.
  Immutable<NonNullPtr<SymbolFile>> object_file;
};

// DAP Result for `variables` request.
struct Variable
{
  int ref;
  SharedPtr<sym::Value> variable_value;
};

}; // namespace ui::dap

namespace fmt {

template <> struct formatter<ui::dap::Scope>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const ui::dap::Scope &scope, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), R"({{ "name": "{}", "presentationHint": "{}", "variablesReference": {} }})",
                          scope.name(), scope.presentation_hint(), scope.variables_reference);
  }
};

template <> struct formatter<ui::dap::Thread>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(ui::dap::Thread const &task, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), "{{ \"id\": {}, \"name\": \"{}\" }}", task.id, task.name);
  }
};

template <> struct formatter<ui::dap::Source>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const ui::dap::Source &source, FormatContext &ctx) const
  {
    return fmt::format_to(ctx.out(), R"({{ "name": "{}", "path": "{}" }})", source.name, source.path);
  }
};
using SourceField = std::optional<ui::dap::Source>;
template <> struct formatter<SourceField>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const SourceField &source, FormatContext &ctx) const
  {
    if (source.has_value()) {
      const auto &src = *source;
      return fmt::format_to(ctx.out(), R"({{ "name": "{}", "path": "{}" }})", src.name, src.path);
    } else {
      return fmt::format_to(ctx.out(), R"(null)");
    }
  }
};

template <> struct formatter<ui::dap::StackFrame>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const ui::dap::StackFrame &frame, FormatContext &ctx) const
  {
    return fmt::format_to(
      ctx.out(),
      R"({{ "id": {}, "name": "{}", "source": {}, "line": {}, "column": {}, "instructionPointerReference": "{}" }})",
      frame.id, frame.name, frame.source, frame.line, frame.column, frame.rip);
  }
};

} // namespace fmt