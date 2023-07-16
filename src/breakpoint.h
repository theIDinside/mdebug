#pragma once
#include "common.h"
#include "symbolication/type.h"

enum class BreakpointType : std::uint8_t
{
  SourceBreakpoint = 0,
  FunctionBreakpoint = 1,
  AddressBreakpoint = 2,
};

class Breakpoint
{
public:
  explicit Breakpoint(AddrPtr, u8 replaced_byte, u32 id, BreakpointType type) noexcept;
  Breakpoint() noexcept = default;
  Breakpoint(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(Breakpoint &&) noexcept = default;

  void enable(Tid tid) noexcept;
  void disable(Tid tid) noexcept;

  u8 ins_byte;
  bool enabled : 1;
  BreakpointType type : 7;
  u16 bp_id;
  u32 times_hit;
  TPtr<void> address;
};