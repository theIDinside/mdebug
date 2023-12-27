#include "callstack.h"
#include "utils/macros.h"

namespace sym {

InsideRange
Frame::inside(TPtr<void> addr) const noexcept
{
  switch (type) {
  case FrameType::Full:
    return addr >= symbol.full_symbol->start_pc() && addr <= symbol.full_symbol->end_pc() ? InsideRange::Yes
                                                                                          : InsideRange::No;
  case FrameType::ElfSymbol:
    return addr >= symbol.min_symbol->start_pc() && addr <= symbol.full_symbol->end_pc() ? InsideRange::Yes
                                                                                         : InsideRange::No;
  case FrameType::Unknown:
    return InsideRange::Unknown;
  }
  MIDAS_UNREACHABLE
}

bool
Frame::has_symbol_info() const noexcept
{
  switch (type) {
  case FrameType::Full:
    return symbol.full_symbol != nullptr;
  case FrameType::ElfSymbol:
    return symbol.min_symbol != nullptr;
  case FrameType::Unknown:
    return false;
  }
  MIDAS_UNREACHABLE
}

FrameType
Frame::frame_type() const noexcept
{
  return type;
}

int
Frame::id() const noexcept
{
  return frame_id;
}

int
Frame::level() const noexcept
{
  return lvl;
}

AddrPtr
Frame::pc() const noexcept
{
  return rip;
}

const sym::FunctionSymbol *
Frame::full_symbol_info() const noexcept
{
  ASSERT(type == FrameType::Full, "Frame has no full symbol info");
  return symbol.full_symbol;
}

const MinSymbol *
Frame::min_symbol_info() const noexcept
{
  ASSERT(type == FrameType::ElfSymbol, "Frame has no ELF symbol info");
  return symbol.min_symbol;
}

std::optional<std::string_view>
Frame::name() const noexcept
{
  return function_name();
}

std::optional<std::string_view>
Frame::function_name() const noexcept
{
  switch (type) {
  case FrameType::Full:
    return symbol.full_symbol->name;
  case FrameType::ElfSymbol:
    return symbol.min_symbol->name;
  case FrameType::Unknown:
    return std::nullopt;
  }
  MIDAS_UNREACHABLE
}

CallStack::CallStack(Tid tid) noexcept : tid(tid), dirty(true), frames(), pcs() {}

const Frame *
CallStack::get_frame(int frame_id) const noexcept
{
  for (const auto &f : frames) {
    if (f.id() == frame_id)
      return &f;
  }
  return nullptr;
}

} // namespace sym