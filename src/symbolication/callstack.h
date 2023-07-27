#pragma once
#include "../common.h"
#include "type.h"
#include <vector>

namespace sym {
enum class FrameType : u8
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
  int level;
  FrameType type;

  friend constexpr bool
  operator==(const Frame &l, const Frame &r) noexcept
  {
    return l.level == r.level && l.cu_file == r.cu_file && l.symbol == r.symbol;
  }
};

struct CallStack
{
  Tid tid;                   // the task associated with this call stack
  std::vector<Frame> frames; // the call stack
  std::optional<int> has_frame(const Frame &f) const noexcept;
};
} // namespace sym