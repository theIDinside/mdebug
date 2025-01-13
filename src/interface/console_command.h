/** LICENSE TEMPLATE */
#pragma once
#include <functional>
#include <memory>
#include <memory_resource>
#include <string>
#include <string_view>
#include <unordered_map>

#define ConsoleLine(FORMAT_STR) FORMAT_STR "\\r\\n"

#define WriteConsoleLine(WRITE_BUFFER, FORMAT_STRING, ...)                                                        \
  fmt::format_to(std::back_inserter(WRITE_BUFFER), FORMAT_STRING "\\r\\n" __VA_OPT__(, ) __VA_ARGS__)

struct ConsoleCommandResult
{
  bool mSuccess;
  std::pmr::string mContents;
};

// Abstract base class for commands, that are called & evaluated via the `EvaluateRequest` request
class ConsoleCommand
{
public:
  virtual ~ConsoleCommand() = default;
  virtual ConsoleCommandResult execute(std::span<std::string_view> args,
                                       std::pmr::memory_resource *allocator) noexcept = 0;
};

// Console Command Registry to store and retrieve commands
class ConsoleCommandRegistry
{
private:
  std::unordered_map<std::string_view, std::shared_ptr<ConsoleCommand>> mCommands;

public:
  void RegisterConsoleCommand(std::string_view name, std::shared_ptr<ConsoleCommand> command) noexcept;
  std::shared_ptr<ConsoleCommand> GetConsoleCommand(std::string_view name) noexcept;
  std::vector<std::string_view> GetCommandNameList() const noexcept;
};

// ConsoleCommandInterpreter
class ConsoleCommandInterpreter
{
private:
  ConsoleCommandRegistry registry;

public:
  void RegisterConsoleCommand(std::string_view name, std::shared_ptr<ConsoleCommand> command) noexcept;
  ConsoleCommandResult Interpret(const std::string &input, std::pmr::memory_resource *allocator) noexcept;
};

/// Commands that are "generic" and installed via `Tracer::SetupConsoleCommands`
/// For now, the system involves just adding a callable. See the current "threads", "stopped", and "resume"
/// commands there The result from the callable is a `ConsoleCommandResult`, that gives the contents as a string
/// and a success flag. This callable is called on the main thread, during the processing of a `EvaluateRequest`
/// DAP event, and as such produces the contents of the resposne for that event.
class GenericCommand : public ConsoleCommand
{
  using Function = std::function<ConsoleCommandResult(std::span<std::string_view>, std::pmr::memory_resource *)>;
  Function mFunction;

  GenericCommand(std::string functionName, Function &&function) noexcept;

public:
  std::string mFunctionName;

  static std::shared_ptr<GenericCommand> CreateCommand(std::string name, Function &&function) noexcept;

  constexpr std::string_view
  CommandName() const noexcept
  {
    return mFunctionName;
  }
  ConsoleCommandResult execute(std::span<std::string_view> args,
                               std::pmr::memory_resource *allocator) noexcept override;
};