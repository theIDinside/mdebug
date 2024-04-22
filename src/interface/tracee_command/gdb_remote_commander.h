#pragma once

#include "tracee_command_interface.h"

namespace tc {
class GdbRemoteCommander : TraceeCommandInterface
{
public:
  static std::unique_ptr<TraceeCommandInterface> createConnection(const GdbRemoteCfg &config) noexcept;
};
} // namespace tc