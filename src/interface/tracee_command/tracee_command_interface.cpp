#include "tracee_command_interface.h"
#include "interface/tracee_command/ptrace_commander.h"

namespace tc {
/*static*/ std::unique_ptr<TraceeCommandInterface>
TraceeCommandInterface::createCommandInterface(const InterfaceConfig &config) noexcept
{
  const auto visitor = CallableOverload{[](const PtraceCfg &config) -> Interface {
                                          DLOG("mdb", "Initializing ptrace interface...");
                                          return std::make_unique<PtraceCommander>(config.tid);
                                        },
                                        [](const GdbRemoteCfg &) -> Interface {
                                          PANIC("GdbRemote protocol support not yet implemented");
                                          DLOG("mdb", "Initializing Gdb Remote Protocol interface...");
                                          return nullptr;
                                        }};
  auto result = std::visit(visitor, config);
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