#include "callstack.h"

namespace sym {

InsideRange
Frame::inside(TPtr<void> addr) const noexcept
{
  if (symbol) {
    return (addr >= symbol->start_pc() && addr < symbol->end_pc()) ? InsideRange::Yes : InsideRange::No;
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

std::optional<std::string_view>
Frame::function_name() const noexcept
{
  if (symbol) {
    return symbol->name;
  } else {
    return std::nullopt;
  }
}

CallStack::CallStack(Tid tid) noexcept : tid(tid), dirty(true), frames(), pcs() {}

const Frame *
CallStack::get_frame(int frame_id) const noexcept
{
  for (const auto &f : frames) {
    if (f.frame_id == frame_id)
      return &f;
  }
  return nullptr;
}

} // namespace sym