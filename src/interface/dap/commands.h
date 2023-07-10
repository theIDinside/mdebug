#pragma once

#include "../../user_commands/commands.h"
#include "dap_defs.h"
#include "nlohmann/json_fwd.hpp"

using Args = nlohmann::json;

namespace ui::dap {

cmd::Continue *continue_command(const Args &args) noexcept;
cmd::Command *parse_command(ui::dap::Command cmd, const Args &args) noexcept;

}; // namespace ui::dap