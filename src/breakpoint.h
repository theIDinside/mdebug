#pragma once
#include "common.h"

class Breakpoint
{
public:
  explicit Breakpoint(u8 replaced_byte, u32 id) noexcept;
  Breakpoint() noexcept = default;
  Breakpoint &operator=(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(Breakpoint &&) noexcept = default;

  u8 ins_byte;
  bool enabled;
  u32 times_hit;
  u32 bp_id;
};