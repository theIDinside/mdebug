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

  static VariableContext
  MakeDependentContext(VariableReferenceId newId, const VariableContext &ctx) noexcept
  {
    return VariableContext{ctx.mTask, ctx.mSymbolFile, ctx.mFrameId, static_cast<u16>(newId),
                           ContextType::Variable};
  }

  bool IsValidContext() const noexcept;
  std::optional<std::array<ui::dap::Scope, 3>> GetScopes(VariableReferenceId frameKey) const noexcept;
  sym::Frame *GetFrame(VariableReferenceId ref) noexcept;
  Ref<sym::Value> GetValue() const noexcept;
};
} // namespace mdb