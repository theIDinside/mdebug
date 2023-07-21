#pragma once
#include "../common.h"
#include "type.h"
#include <vector>

namespace sym {
enum class FrameType
{
  Full,
  Unknown
};

enum class InsideRange
{
  Yes,
  No,
  Unknown
};

struct Frame
{
  InsideRange inside(TPtr<void> addr) const noexcept;
  std::optional<std::string_view> name() const noexcept;
  TPtr<void> rip;
  const FunctionSymbol *symbol;
  const CompilationUnitFile *cu_file;
  FrameType type;
};

struct CallStack
{
  Tid tid;                   // the task associated with this call stack
  std::vector<Frame> frames; // the call stack
};
} // namespace sym