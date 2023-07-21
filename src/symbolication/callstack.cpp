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

} // namespace sym