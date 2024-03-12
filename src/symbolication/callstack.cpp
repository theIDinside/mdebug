#include "callstack.h"
#include "common.h"
#include "symbolication/block.h"
#include "symbolication/dwarf/debug_info_reader.h"
#include "utils/macros.h"
#include <symbolication/cu_symbol_info.h>

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

SymbolFile *
Frame::get_symbol_file() noexcept
{
  return symbol_file;
}

const sym::FunctionSymbol &
Frame::full_symbol_info() const noexcept
{
  auto ptr = maybe_get_full_symbols();
  if (ptr == nullptr) {
    PANIC("No symbol information for frame, but expected there to be one");
  }
  return *ptr;
}

std::optional<dw::LineTable>
Frame::cu_line_table() const noexcept
{
  if (type != FrameType::Full)
    return std::nullopt;
  const auto symbol_info = symbol.full_symbol->symbol_info();
  ASSERT(symbol_info != nullptr, "Expected symbol info for this frame to not be null");

  return symbol_info->get_linetable(symbol_file);
}

sym::FunctionSymbol *
Frame::maybe_get_full_symbols() const noexcept
{
  ASSERT(type == FrameType::Full, "Frame has no full symbol info");
  return symbol.full_symbol;
}

const MinSymbol *
Frame::maybe_get_min_symbols() const noexcept
{
  ASSERT(type == FrameType::ElfSymbol, "Frame has no ELF symbol info");
  return symbol.min_symbol;
}

IterateFrameSymbols
Frame::block_symbol_iterator(FrameVariableKind variables_kind) noexcept
{
  return IterateFrameSymbols{*this, variables_kind};
}

u32
Frame::frame_locals_count() const noexcept
{
  return full_symbol_info().local_variable_count();
}

u32
Frame::frame_args_count() const noexcept
{
  return full_symbol_info().get_args().symbols.size();
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

Frame *
CallStack::get_frame(int frame_id) noexcept
{
  for (auto &f : frames) {
    if (f.id() == frame_id)
      return &f;
  }
  return nullptr;
}

} // namespace sym