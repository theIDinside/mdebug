/** LICENSE TEMPLATE */
#include "types.h"
#include <iterator>
#include <memory_resource>
#include <supervisor.h>
#include <symbolication/value.h>

namespace mdb::ui::dap {

std::pmr::string
Breakpoint::Serialize(std::pmr::memory_resource *memoryResource) const noexcept
{
  std::pmr::string buf{ memoryResource };
  // TODO(simon): Here we really should be using some form of arena allocation for the DAP interpreter
  // communication
  //  so that all these allocations can be "blinked" out of existence, i.e. all serialized command results, will be
  //  manually de/allocated by us. But that's the future.
  buf.reserve(256);
  auto it = std::back_inserter(buf);
  it = std::format_to(it, R"({{"id":{},"verified":{})", mId, mVerified);
  if (mVerified) {
    it = std::format_to(it, R"(,"instructionReference": "{}")", mAddress);
  } else {
    it = std::format_to(it, R"(,"message": "{}")", mErrorMessage.value());
  }

  if (mLine) {
    it = std::format_to(it, R"(,"line": {})", *mLine);
  }

  if (mColumn) {
    it = std::format_to(it, R"(,"column": {})", *mColumn);
  }
  if (mSourcePath) {
    it = std::format_to(it, R"(,"source": {{ "name": "{}", "path": "{}" }})", *mSourcePath, *mSourcePath);
  }
  it = std::format_to(it, R"(}})");
  return buf;
}

/*static*/
Breakpoint
Breakpoint::CreateNonVerified(u32 id, std::string_view msg) noexcept
{
  return Breakpoint{ .mId = id,
    .mVerified = false,
    .mAddress = nullptr,
    .mLine = {},
    .mColumn = {},
    .mSourcePath = {},
    .mErrorMessage = std::string{ msg } };
}

Breakpoint
Breakpoint::CreateFromUserBreakpoint(const UserBreakpoint &userBreakpoint) noexcept
{
  if (const auto addr = userBreakpoint.Address(); addr) {
    return Breakpoint{ .mId = userBreakpoint.mId,
      .mVerified = true,
      .mAddress = addr.value(),
      .mLine = userBreakpoint.Line(),
      .mColumn = userBreakpoint.Column(),
      .mSourcePath = userBreakpoint.GetSourceFile(),
      .mErrorMessage = {} };
  } else {
    return Breakpoint{ .mId = userBreakpoint.mId,
      .mVerified = false,
      .mAddress = nullptr,
      .mLine = {},
      .mColumn = {},
      .mSourcePath = {},
      .mErrorMessage = userBreakpoint.GetErrorMessage() };
  }
}

VariablesReference::VariablesReference(
  NonNullPtr<SymbolFile> objectFile, int ref, int thread, int frameId, int parent, EntityType type) noexcept
    : mId(ref), mThreadId(thread), mFrameId(frameId), mParentId(parent), mType(type), mScopeType(),
      mObjectFile(objectFile)
{
}

VariablesReference::VariablesReference(NonNullPtr<SymbolFile> objectFile,
  int ref,
  int thread,
  int frameId,
  int parent,
  EntityType type,
  ScopeType scopeType) noexcept
    : mId(ref), mThreadId(thread), mFrameId(frameId), mParentId(parent), mType(type), mScopeType(scopeType),
      mObjectFile(objectFile)
{
}

bool
VariablesReference::HasParent() const noexcept
{
  return 0 != *mParentId;
}

std::optional<int>
VariablesReference::ParentVariablesReference() const noexcept
{
  if (HasParent()) {
    return mParentId;
  } else {
    return std::nullopt;
  }
}
}; // namespace mdb::ui::dap