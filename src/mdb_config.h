/** LICENSE TEMPLATE */
#pragma once
#include "utils/expected.h"
#include <filesystem>
#include <linux/limits.h>
#include <optional>

// system namespace - anything and everything that involves the configuration of mdb
namespace mdb::sys {

enum class CLIErrorInfo
{
  UnknownArgs,
  BadArgValue
};

struct CLIError
{
  CLIErrorInfo info;
  std::string msg;
};

class DebuggerConfiguration
{
  std::optional<int> mThreadPoolSize{ std::nullopt };
  Path mLogDirectory;
  std::vector<std::string> mLogModules;

public:
  static auto
  Default() noexcept
  {
    auto res = DebuggerConfiguration{};
    res.mLogDirectory = std::filesystem::current_path();
    return res;
  }

  int ThreadPoolSize() const noexcept;
  const Path &LogDirectory() const noexcept;
};

mdb::Expected<DebuggerConfiguration, CLIError> ParseCommandLineArguments(int argc, const char **argv) noexcept;

}; // namespace mdb::sys