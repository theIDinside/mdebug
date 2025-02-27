/** LICENSE TEMPLATE */
#pragma once
#include "utils/expected.h"
#include <filesystem>
#include <linux/limits.h>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_set>

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

// Awaiter thread should be used in most circumstances; but this system won't function under RR (yet).
// So if MDB is to be recorded by RR, the signal handler system should be used instead.
enum class WaitSystem
{
  UseAwaiterThread,
  UseSignalHandler,
};

template <typename ConfigType> struct Setting
{
  std::string_view setting;
  ConfigType boolean;
};

using namespace std::string_view_literals;

class DebuggerConfiguration
{
  WaitSystem mWaitSystem{WaitSystem::UseAwaiterThread};
  std::optional<int> mThreadPoolSize{std::nullopt};
  Path mLogDirectory;

public:
  friend mdb::Expected<DebuggerConfiguration, CLIError> ParseCommandLineArguments(int argc,
                                                                                  const char **argv) noexcept;

  static auto
  Default() noexcept
  {
    auto res = DebuggerConfiguration{};
    res.mLogDirectory = std::filesystem::current_path();
    return res;
  }

  WaitSystem GetWaitSystemConfig() const noexcept;
  int ThreadPoolSize() const noexcept;
  const Path &LogDirectory() const noexcept;
};

mdb::Expected<DebuggerConfiguration, CLIError> ParseCommandLineArguments(int argc, const char **argv) noexcept;

}; // namespace mdb::sys