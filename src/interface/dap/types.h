#pragma once
#include "../../common.h"
#include "../../symbolication/callstack.h"
#include <fmt/format.h>
#include <string_view>
namespace ui::dap {

struct SourceBreakpoint
{
  int line;
  std::optional<int> column;
  std::optional<std::string> condition;
  std::optional<std::string> hit_condition;
  std::optional<std::string> logMessage;
};

struct FunctionBreakpoint
{
  std::string name;
  std::optional<std::string> condition;
  std::optional<std::string> hit_condition;
};

struct InstructionBreakpoint
{
};

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
  TPtr<void> addr;

  std::optional<u32> line;
  std::optional<u32> col;
  std::optional<std::string_view> source_path;
  std::optional<std::string_view> error_message;

  std::string serialize() const noexcept;
  static Breakpoint non_verified(u32 id, std::string_view msg) noexcept;
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
  std::string name;
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

struct Scope
{
  std::string_view name;
  std::string_view presentation_hint;
  int variables_reference;
};

enum class EntityType
{
  Scope,
  Frame,
  Variable
};

struct VariablesReference
{
  bool has_parent() const noexcept;
  std::optional<int> parent() const noexcept;
  // The execution context (Task) that this variable reference exists in
  int thread_id;
  // The frame id this variable reference exists in
  int frame_id;
  // (Possible) parent reference. A scope has a frame as it's parent. A variable has a scope or another variable as
  // it's parent. To walk up the hierarchy, one would read the variables reference map using the parent key
  int parent_;
  // The reference type
  EntityType type;
};

// DAP Result for `variables` request.
struct Variable
{
  int ref;
  std::string_view name;
  std::string_view type;
  std::string value;
  AddrPtr mem_ref;
};

}; // namespace ui::dap

namespace fmt {

template <> struct formatter<ui::dap::Variable>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const ui::dap::Variable &var, FormatContext &ctx) const
  {
    return fmt::format_to(
        ctx.out(), R"({{ "name": "{}", "value": "{}", "variablesReference": {}, "memoryReference": "{}" }})",
        var.name, var.value, var.ref, var.mem_ref);
  }
};

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
                          scope.name, scope.presentation_hint, scope.variables_reference);
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