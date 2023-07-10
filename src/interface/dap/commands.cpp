#include "commands.h"
#include "nlohmann/json.hpp"

namespace ui::dap {
cmd::Continue *
continue_command(const Args &args) noexcept
{
  auto cmd = new cmd::Continue{};
  args.at("threadId").get_to(cmd->thread_id);
  if (args.contains("singleThread"))
    args.at("singleThread").get_to(cmd->continue_all);
  else
    cmd->continue_all = true;
  return cmd;
}

cmd::Command *
parse_command(ui::dap::Command cmd, const Args &args) noexcept
{
  switch (cmd) {
  case Command::Continue:
    return continue_command(args);
  case Command::Attach:
  case Command::BreakpointLocations:
  case Command::Completions:
  case Command::ConfigurationDone:
  case Command::CustomRequest:
  case Command::DataBreakpointInfo:
  case Command::Disassemble:
  case Command::Disconnect:
  case Command::Evaluate:
  case Command::ExceptionInfo:
  case Command::Goto:
  case Command::GotoTargets:
  case Command::Initialize:
  case Command::Launch:
  case Command::LoadedSources:
  case Command::Modules:
  case Command::Next:
  case Command::Pause:
  case Command::ReadMemory:
  case Command::Restart:
  case Command::RestartFrame:
  case Command::ReverseContinue:
  case Command::Scopes:
  case Command::SetBreakpoints:
  case Command::SetDataBreakpoints:
  case Command::SetExceptionBreakpoints:
  case Command::SetExpression:
  case Command::SetFunctionBreakpoints:
  case Command::SetInstructionBreakpoints:
  case Command::SetVariable:
  case Command::Source:
  case Command::StackTrace:
  case Command::StepBack:
  case Command::StepIn:
  case Command::StepInTargets:
  case Command::StepOut:
  case Command::Terminate:
  case Command::TerminateThreads:
  case Command::Threads:
  case Command::Variables:
  case Command::WriteMemory:
  case Command::UNKNOWN:
    PANIC(fmt::format("Unimplemented command {}", to_str(cmd)));
  }
  return nullptr;
}
}; // namespace ui::dap