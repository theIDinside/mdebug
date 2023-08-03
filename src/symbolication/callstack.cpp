#include "callstack.h"

namespace sym {

InsideRange
Frame::inside(TPtr<void> addr) const noexcept
{
  if (symbol) {
    return (addr >= symbol->start && addr < symbol->end) ? InsideRange::Yes : InsideRange::No;
  } else
    return InsideRange::Unknown;
}

std::optional<std::string_view>
Frame::name() const noexcept
{
  if (!symbol)
    return std::nullopt;
  else
    return symbol->name;
}

std::optional<int>
CallStack::has_frame(const Frame &f) const noexcept
{
  auto i = 0;
  for (const auto &frame : frames) {
    if (frame == f)
      return i;
    ++i;
  }
  return std::nullopt;
}

std::optional<std::string_view>
Frame::function_name() const noexcept
{
  if (symbol) {
    return symbol->name;
  } else {
    return std::nullopt;
  }
}

CallStack::CallStack(Tid tid) noexcept : tid(tid), frames(), pcs(), dirty(true) {}

} // namespace sym