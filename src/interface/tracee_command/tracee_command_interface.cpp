#include "tracee_command_interface.h"
#include "common.h"
#include "interface/tracee_command/gdb_remote_commander.h"
#include "interface/tracee_command/ptrace_commander.h"
#include <type_traits>

namespace tc {
/*static*/ std::unique_ptr<TraceeCommandInterface>
TraceeCommandInterface::createCommandInterface(const InterfaceConfig &config) noexcept
{
  Interface result = std::visit(
      [](const auto &config) -> Interface {
        using T = std::remove_cvref_t<decltype(config)>;
        if constexpr (std::is_same_v<PtraceCfg, T>) {
          DLOG("mdb", "Initializing ptrace interface...");
          return std::make_unique<PtraceCommander>(config.tid);
        } else if constexpr (std::is_same_v<GdbRemoteCfg, T>) {
          DLOG("mdb", "Initializing remote protocol interface...");
          return GdbRemoteCommander::createConnection(config);
        } else {
          static_assert(always_false<T>, "Unsupported type T");
        }
      },
      config);
  return result;
}

std::string_view
to_str(RunType type) noexcept
{
  switch (type) {
  case RunType::Step:
    return "RunType::Step";
  case RunType::Continue:
    return "RunType::Continue";
  case RunType::SyscallContinue:
    return "RunType::SyscallContinue";
  case RunType::UNKNOWN:
    return "RunType::UNKNOWN";
    break;
  }
  __builtin_unreachable();
}

} // namespace tc