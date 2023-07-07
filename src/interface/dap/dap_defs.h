#pragma once

#include <cstdint>
#include <string_view>

namespace ui::dap {

enum class Command : std::uint8_t
{
#define DAP_COMMANDS
#define ITEM(name, value) name = value,
#include "dap.defs"
#undef ITEM
#undef DAP_COMMANDS
  UNKNOWN
};

constexpr std::string_view
to_str(Command command) noexcept
{
#define DAP_COMMANDS
#define ITEM(name, value)                                                                                         \
  case Command::name:                                                                                             \
    return #name;
  switch (command) {
#include "dap.defs"
  case Command::UNKNOWN:
    return "Unknown command type";
  }
#undef ITEM
#undef DAP_COMMANDS
}

// We sent events, we never receive them, so an "UNKNOWN" value is unnecessary.
// or better put; Events are an "output" type only.
enum class Events : std::uint8_t
{
#define DAP_EVENTS
#define ITEM(name, value) name = value,
#include "dap.defs"
#undef ITEM
#undef DAP_EVENTS
};

constexpr std::string_view
to_str(Events command) noexcept
{
#define DAP_EVENTS
#define ITEM(name, value)                                                                                         \
  case Events::name:                                                                                              \
    return #name;
  switch (command) {
#include "dap.defs"
  }
#undef ITEM
#undef DAP_EVENTS
}

} // namespace ui::dap