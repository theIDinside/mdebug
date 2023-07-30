#pragma once
#include "common.h"

enum class BreakpointType : std::uint8_t
{
  SourceBreakpoint = 1 << 0,
  FunctionBreakpoint = 1 << 1,
  AddressBreakpoint = 1 << 2
};

struct SourceBreakpointDescriptor
{
  std::string_view source_file;
  u32 line;
  std::optional<u32> column;
  std::optional<std::string> condition;
  std::optional<int> hit_condition;
  std::optional<std::string> log_message;
};

class Breakpoint
{
public:
  explicit Breakpoint(AddrPtr, u8 original_byte, u32 id, BreakpointType type) noexcept;
  Breakpoint() noexcept = default;
  Breakpoint(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(Breakpoint &&) noexcept = default;

  void enable(Tid tid) noexcept;
  void disable(Tid tid) noexcept;
  BreakpointType type() const noexcept;

  u8 original_byte;
  bool enabled : 1;
  BreakpointType bp_type : 7;
  u16 id;
  u32 times_hit;
  TPtr<void> address;
};