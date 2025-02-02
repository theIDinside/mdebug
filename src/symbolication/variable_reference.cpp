/** LICENSE TEMPLATE */
#include "variable_reference.h"
#include "symbolication/value.h"
#include "utils/macros.h"
#include <task.h>

namespace mdb {
bool
VariableContext::IsValidContext() const noexcept
{
  return mTask != nullptr;
}

std::optional<std::array<ui::dap::Scope, 3>>
VariableContext::GetScopes(VariableReferenceId frameKey) const noexcept
{
  auto frame = mTask->get_callstack().GetFrame(frameKey);
  if (!frame) {
    return {};
  } else {
    return frame->Scopes();
  }
}

sym::Frame *
VariableContext::GetFrame(VariableReferenceId ref) noexcept
{
  switch (mType) {
  case ContextType::Frame:
    return mTask->get_callstack().GetFrame(ref);
  case ContextType::Scope:
  case ContextType::Variable:
    return mTask->get_callstack().GetFrame(mFrameId);
  case ContextType::Global:
    PANIC("Global variables not yet supported");
    break;
  }
  NEVER("Unknown context type");
}

Ref<sym::Value>
VariableContext::GetValue() const noexcept
{
  return mTask->GetVariablesReference(mId);
}
} // namespace mdb