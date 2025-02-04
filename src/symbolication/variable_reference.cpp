/** LICENSE TEMPLATE */
#include "variable_reference.h"
#include "symbolication/value.h"
#include "utils/macros.h"
#include <task.h>

namespace mdb {
VariableContext::VariableContext(TaskInfo *task, SymbolFile *symbolFile, VariableReferenceId frameId,
                                 VariableReferenceId varRefId, ContextType type) noexcept
    : mTask(task), mSymbolFile(symbolFile), mFrameId(frameId), mId(varRefId), mType(type)
{
}

bool
VariableContext::IsLiveReference() const noexcept
{
  if (!mTask) {
    return false;
  }
  return !mTask->VariableReferenceIsStale(mId);
}

bool
VariableContext::IsValidContext() const noexcept
{
  return mTask != nullptr;
}

std::optional<std::array<ui::dap::Scope, 3>>
VariableContext::GetScopes(VariableReferenceId frameKey) const noexcept
{
  auto frame = mTask->GetCallstack().GetFrame(frameKey);
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
    return mTask->GetCallstack().GetFrame(ref);
  case ContextType::Scope:
  case ContextType::Variable:
    return mTask->GetCallstack().GetFrame(mFrameId);
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

// static
std::shared_ptr<VariableContext>
VariableContext::FromFrame(VariableReferenceId varRefId, ContextType type, const sym::Frame &frame) noexcept
{
  return std::make_shared<VariableContext>(frame.Task(), frame.GetSymbolFile(), frame.FrameId(), varRefId, type);
}

} // namespace mdb