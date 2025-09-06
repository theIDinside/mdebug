/** LICENSE TEMPLATE */
#pragma once
// mdb
#include "common/formatter.h"
#include <common/macros.h>
#include <common/panic.h>
#include <common/typedefs.h>
#include <symbolication/value.h>
#include <symbolication/variable_reference.h>
#include <tracee_pointer.h>
#include <utils/immutable.h>

// stdlib
#include <string_view>

namespace std::pmr {
class memory_resource;
}
namespace mdb {
class SymbolFile;
class UserBreakpoint;

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
  u32 mId;
  // verified
  bool mVerified;
  // instructionReference
  AddrPtr mAddress;

  std::optional<u32> mLine;
  std::optional<u32> mColumn;
  std::optional<std::string_view> mSourcePath;
  std::optional<std::pmr::string> mErrorMessage;

  std::pmr::string Serialize(std::pmr::memory_resource *memoryResource) const noexcept;
  static Breakpoint CreateNonVerified(u32 id, std::string_view msg, std::pmr::memory_resource *rsrc) noexcept;
  static Breakpoint CreateFromUserBreakpoint(
    const UserBreakpoint &userBreakpoint, std::pmr::memory_resource *rsrc) noexcept;
};

struct DataBreakpoint
{
  std::string mDataBreakpointId;
  std::string_view mAccessType;
  std::string mCondition;
  std::string mHitCondition;
};

struct Thread
{
  int mThreadId;
  std::string_view mName;
};

struct StackFrame
{
  VariableReferenceId mVariablesReference;
  std::string_view mName;
  std::optional<Source> mSource;
  int mLine;
  int mColumn;
  std::string mProgramCounter;
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
  VariableReferenceId variables_reference{};

  constexpr std::string_view
  Name() const noexcept
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
  PresentationHint() const noexcept
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

enum class EntityType : std::uint8_t
{
  Scope,
  Frame,
  Variable
};

class VariablesReference
{
public:
  VariablesReference(
    NonNullPtr<SymbolFile> obj, int ref, int thread, int frameId, int parent, EntityType type) noexcept;
  VariablesReference(NonNullPtr<SymbolFile> obj,
    int ref,
    int thread,
    int frameId,
    int parent,
    EntityType type,
    ScopeType scopeType) noexcept;
  VariablesReference &operator=(const VariablesReference &) = default;
  VariablesReference &operator=(VariablesReference &&) = default;
  VariablesReference(VariablesReference &&) = default;
  VariablesReference(const VariablesReference &) = default;

  bool HasParent() const noexcept;
  std::optional<int> ParentVariablesReference() const noexcept;

  // actual variablesReference value
  Immutable<int> mId;
  // The execution context (Task) that this variable reference exists in
  Immutable<int> mThreadId;
  // The frame id this variable reference exists in
  Immutable<int> mFrameId;
  // (Possible) parent reference. A scope has a frame as it's parent. A variable has a scope or another variable as
  // it's parent. To walk up the hierarchy, one would read the variables reference map using the parent key
  Immutable<int> mParentId;
  // The reference type
  Immutable<EntityType> mType;
  // TODO(simon): INCREDIBLE HACK. We should refactor VariablesReferences. See "our own" implementation in Midas
  // (though written in Python). That is a better solution than having to carry this extra field for a WHOLE BUNCH
  // of variables references that aren't of "scope type"
  Immutable<std::optional<ScopeType>> mScopeType;

  // The "symbol context" for this variable reference.
  // Keep it a NonNullPtr<ObjectFile> instead of a reference, because we want pointer comparison for equality /
  // identify. Because only 1 objectfile of some binary will *ever* be loaded into memory.
  Immutable<NonNullPtr<SymbolFile>> mObjectFile;
};
}; // namespace ui::dap
} // namespace mdb

namespace ui = mdb::ui;

template <> struct std::formatter<ui::dap::Scope>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const ui::dap::Scope &scope, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(),
      R"({{ "name": "{}", "presentationHint": "{}", "variablesReference": {} }})",
      scope.Name(),
      scope.PresentationHint(),
      scope.variables_reference);
  }
};

template <> struct std::formatter<ui::dap::Thread>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(ui::dap::Thread const &task, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(), "{{ \"id\": {}, \"name\": \"{}\" }}", task.mThreadId, task.mName);
  }
};

template <> struct std::formatter<ui::dap::Source>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const ui::dap::Source &source, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(), R"({{ "name": "{}", "path": "{}" }})", source.name, source.path);
  }
};
using SourceField = std::optional<ui::dap::Source>;
template <> struct std::formatter<SourceField>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const SourceField &source, FormatContext &ctx) const
  {
    if (source.has_value()) {
      const auto &src = *source;
      return std::format_to(ctx.out(), R"({{ "name": "{}", "path": "{}" }})", src.name, src.path);
    } else {
      return std::format_to(ctx.out(), R"(null)");
    }
  }
};

template <> struct std::formatter<ui::dap::StackFrame>
{
  BASIC_PARSE

  template <typename FormatContext>
  auto
  format(const ui::dap::StackFrame &frame, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(),
      R"({{ "id": {}, "name": "{}", "source": {}, "line": {}, "column": {}, "instructionPointerReference": "{}" }})",
      frame.mVariablesReference,
      frame.mName,
      frame.mSource,
      frame.mLine,
      frame.mColumn,
      frame.mProgramCounter);
  }
};