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

struct Frame
{
  bool inside(TPtr<void> addr) const noexcept;
  TPtr<void> start, end;                   // retrieved from DWARF debug information
  TPtr<void> rip;                          // Where inside the frame are we?
  std::optional<std::string_view> fn_name; // possible function name associated with this frame
  CompilationUnitFile *cu_file;
  FrameType type;
};

struct CallStack
{
  // Takes an `addr` and finds the first frame where that addr exists and pops the frames above it
  // Example:
  // Task A has stopped at a new address %rip = 0xf00
  //  %foo can be found at frames[-5]; remove the remaining 4 (-5 is the 5th element before the end)
  // returns true if stack was changed, false if not
  bool trim_stack(TPtr<void> addr) noexcept;
  Tid tid;                   // the task associated with this call stack
  std::vector<Frame> frames; // the call stack
};
} // namespace sym