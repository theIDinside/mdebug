/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common.h>
#include <configuration/command_line.h>
#include <utils/log_channel.h>
// std
// system

namespace mdb::cfg {

enum class InterfaceType : u8
{
  StandardIO,
  Unix
};

struct CommunicationInterface
{
  InterfaceType mType;
  // StandardIO has no path
  std::string_view mPath;
};

enum class Transport : u8
{
  UnixSocket
};

struct UseStdio
{
};

struct UnixSocket
{
  std::string_view mPath;
};

// Adding new interfaces (e.g. tcp:host:port) is trivial, add a new type struct TcpSocket { ... }
using DebugAdapterInterface = std::variant<UseStdio, UnixSocket>;

class InitializationConfiguration
{
  // Construction only allowed via `ConfigureWithParser`
  constexpr InitializationConfiguration() noexcept = default;

public:
  size_t mThreadPoolSize;
  std::filesystem::path mLogDirectory;
  DebugAdapterInterface mDebugAdapterInterface;
  int mWaitForConnectionTimeout;
  std::vector<Channel> mLogChannels;

  static InitializationConfiguration *ConfigureWithParser(CommandLineRegistry &parser) noexcept;
};
} // namespace mdb::cfg