/** LICENSE TEMPLATE */
#include "console_command.h"
#include "mdbjs/mdbjs.h"
#include <tracer.h>
#include <utility>

/// ConsoleCommandRegistry implementation
namespace mdb {
namespace fmt = ::fmt;
void
ConsoleCommandRegistry::RegisterConsoleCommand(std::string_view name,
                                               std::shared_ptr<ConsoleCommand> command) noexcept
{
  mCommands[name] = std::move(command);
}

std::shared_ptr<ConsoleCommand>
ConsoleCommandRegistry::GetConsoleCommand(std::string_view name) noexcept
{
  auto it = mCommands.find(name);
  if (it != mCommands.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

std::vector<std::string_view>
ConsoleCommandRegistry::GetCommandNameList() const noexcept
{
  std::vector<std::string_view> result;
  result.reserve(mCommands.size());
  for (const auto &[name, command] : mCommands) {
    result.push_back(name);
  }
  return result;
}

/// ConsoleCommandInterpreter Implementations
void
ConsoleCommandInterpreter::RegisterConsoleCommand(std::string_view name,
                                                  std::shared_ptr<ConsoleCommand> command) noexcept
{
  registry.RegisterConsoleCommand(name, std::move(command));
}

ConsoleCommandResult
ConsoleCommandInterpreter::Interpret(const std::string &input, Allocator *allocator) noexcept
{
  auto result = Tracer::GetScriptingInstance().ReplEvaluate(input, allocator);
  return ConsoleCommandResult{true, result};
}

GenericCommand::GenericCommand(std::string functionName, Function &&function) noexcept
    : mFunction(std::move(function)), mFunctionName(std::move(functionName))
{
}

/* static */
std::shared_ptr<GenericCommand>
GenericCommand::CreateCommand(std::string name, GenericCommand::Function &&function) noexcept
{
  return std::shared_ptr<GenericCommand>(new GenericCommand{std::move(name), std::move(function)});
}

ConsoleCommandResult
GenericCommand::execute(std::span<std::string_view> args, std::pmr::memory_resource *allocator) noexcept
{
  return mFunction(args, allocator);
}
} // namespace mdb