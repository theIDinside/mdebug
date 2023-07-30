#include "breakpoint.h"
#include <sys/ptrace.h>

Breakpoint::Breakpoint(AddrPtr addr, u8 original_byte, u32 id, UserBreakpointType type) noexcept
    : original_byte(original_byte), enabled(true), bp_type(type), id(id), times_hit(0), address(addr)
{
}

void
Breakpoint::enable(Tid tid) noexcept
{
  constexpr u64 bkpt = 0xcc;
  const auto read_value = ptrace(PTRACE_PEEKDATA, tid, address.get(), nullptr);
  const u64 installed_bp = ((read_value & ~0xff) | bkpt);
  ptrace(PTRACE_POKEDATA, tid, address.get(), installed_bp);
  enabled = true;
}

void
Breakpoint::disable(Tid tid) noexcept
{
  const auto read_value = ptrace(PTRACE_PEEKDATA, tid, address.get(), nullptr);
  const u64 restore = ((read_value & ~0xff) | original_byte);
  ptrace(PTRACE_POKEDATA, tid, address.get(), restore);
  enabled = false;
}

UserBreakpointType
Breakpoint::type() const noexcept
{
  return bp_type;
}
