#include "console_command.h"
#include "fmt/ranges.h"
#include "utils/util.h"
#include <iterator>
#include <tracer.h>
#include <utility>

/// ConsoleCommandRegistry implementation

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
ConsoleCommandInterpreter::Interpret(const std::string &input, std::pmr::memory_resource *allocator) noexcept
{
  auto splitInput = utils::split_string(input, " ");

  if (splitInput.empty()) {
    return ConsoleCommandResult{false, std::pmr::string{ConsoleLine("No input for command"), allocator}};
  }

  std::string_view commandName = splitInput[0];
  auto args = std::span{splitInput}.subspan(1);

  auto command = registry.GetConsoleCommand(commandName);
  if (command) {
    return command->execute(args, allocator);
  } else {
    std::pmr::string msg{"", allocator};
    WriteConsoleLine(msg, "Unknown command: {}", commandName);
    WriteConsoleLine(msg, "Possible commands {}", fmt::join(registry.GetCommandNameList(), ", "));
    return ConsoleCommandResult{false, std::move(msg)};
  }
}

GenericCommand::GenericCommand(std::string functionName, Function &&function) noexcept
    : mFunctionName(std::move(functionName)), mFunction(std::move(function))
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