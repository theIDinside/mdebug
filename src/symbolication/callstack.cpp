#include "callstack.h"

namespace sym {

bool
Frame::inside(TPtr<void> addr) const noexcept
{
  return addr >= start && addr <= end;
}

bool
CallStack::trim_stack(TPtr<void> addr) noexcept
{
  if (frames.back().inside(addr))
    return false;
  const auto sz = frames.size();
  auto it = find(frames, [addr](const auto &frame) { return frame.inside(addr); });
  it = (std::end(frames) == it) ? it : it + 1;
  frames.erase(it, std::end(frames));
  return sz != frames.size();
}

} // namespace sym