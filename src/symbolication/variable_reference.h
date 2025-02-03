/** LICENSE TEMPLATE */
#pragma once
#include "typedefs.h"
#include <optional>
#include <utils/smartptr.h>

namespace mdb::ui::dap {
class Scope;
}

namespace mdb::sym {
class Frame;
class Value;
} // namespace mdb::sym

namespace mdb {

using VariableReferenceId = u64;

class TaskInfo;
class SymbolFile;

enum class ContextType : u8
{
  Frame,
  Scope,
  Variable,
  Global,
};

struct VariableContext
{
  TaskInfo *mTask{nullptr};
  SymbolFile *mSymbolFile{nullptr};
  VariableReferenceId mFrameId{0};
  VariableReferenceId mId{0};
  ContextType mType{ContextType::Global};

  VariableContext() noexcept = default;
  VariableContext(TaskInfo *task, SymbolFile *symbolFile, VariableReferenceId frameId,
                  VariableReferenceId varRefId, ContextType type) noexcept;

  VariableContext(const VariableContext &) noexcept = default;

  static VariableContext
  MakeDependentContext(VariableReferenceId newId, const VariableContext &ctx) noexcept
  {
    return VariableContext{ctx.mTask, ctx.mSymbolFile, ctx.mFrameId, newId, ContextType::Variable};
  }

  static std::shared_ptr<VariableContext>
  CloneFrom(VariableReferenceId newId, const VariableContext &ctx) noexcept
  {
    return std::make_shared<VariableContext>(ctx.mTask, ctx.mSymbolFile, ctx.mFrameId, newId, ctx.mType);
  }

  static std::shared_ptr<VariableContext> FromFrame(VariableReferenceId varRefId, ContextType type,
                                                    const sym::Frame &frame) noexcept;

  bool IsLiveReference() const noexcept;
  bool IsValidContext() const noexcept;
  std::optional<std::array<ui::dap::Scope, 3>> GetScopes(VariableReferenceId frameKey) const noexcept;
  sym::Frame *GetFrame(VariableReferenceId ref) noexcept;
  Ref<sym::Value> GetValue() const noexcept;
};
} // namespace mdb