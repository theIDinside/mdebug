#include "breakpoint.h"

Breakpoint::Breakpoint(AddrPtr addr, u8 replaced_byte, u32 id, BreakpointType type) noexcept
    : ins_byte(replaced_byte), enabled(true), type(type), bp_id(id), times_hit(0), address(addr)
{
}
