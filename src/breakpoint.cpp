#include "breakpoint.h"

Breakpoint::Breakpoint(u8 replaced_byte, u32 id) noexcept
    : ins_byte(replaced_byte), enabled(true), times_hit(0), bp_id(id)
{
}