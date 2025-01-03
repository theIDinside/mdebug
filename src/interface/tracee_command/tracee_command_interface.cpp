#include "tracee_command_interface.h"
#include "common.h"
#include "interface/tracee_command/ptrace_commander.h"
#include <supervisor.h>
#include <tracer.h>
#include <type_traits>

namespace tc {

TraceeCommandInterface::TraceeCommandInterface(TargetFormat format,
                                               std::shared_ptr<gdb::ArchictectureInfo> &&arch_info,
                                               TraceeInterfaceType type) noexcept
    : format(format), arch_info(std::move(arch_info)), mType(type)
{
}

/*static*/ Interface
TraceeCommandInterface::CreateCommandInterface(const InterfaceConfig &config) noexcept
{
  Interface result = std::visit(
    [](const auto &config) -> Interface {
      using T = std::remove_cvref_t<decltype(config)>;
      if constexpr (std::is_same_v<PtraceCfg, T>) {
        DBGLOG(core, "Initializing ptrace interface...");
        return std::make_unique<PtraceCommander>(config.tid);
      } else if constexpr (std::is_same_v<GdbRemoteCfg, T>) {
        TODO("Implement createCommandInterface via add_target_set_current");
      } else {
        static_assert(always_false<T>, "Unsupported type T");
      }
    },
    config);
  return result;
}

bool
TraceeCommandInterface::TargetManagesBreakpoints() noexcept
{
  return false;
}

TaskExecuteResponse
TraceeCommandInterface::ReverseContinue() noexcept
{
  return TaskExecuteResponse::Error(0);
}

TaskExecuteResponse
TraceeCommandInterface::DoDisconnect(bool terminate) noexcept
{
  for (auto &user : tc->GetUserBreakpoints().all_users()) {
    tc->GetUserBreakpoints().remove_bp(user->id);
  }
  Disconnect(terminate);
  return TaskExecuteResponse::Ok();
}

std::optional<std::string>
TraceeCommandInterface::ReadNullTerminatedString(TraceePointer<char> address, u32 buffer_size) noexcept
{
  std::string result{};
  if (address == nullptr) {
    return std::nullopt;
  }
  u8 buf[buffer_size];
  auto res = ReadBytes(address.as<void>(), buffer_size, buf);
  while (res.success()) {
    for (auto i = 0u; i < res.bytes_read; ++i) {
      if (buf[i] == 0) {
        return result;
      }
      result.push_back(buf[i]);
    }
    res = ReadBytes(address.as<void>(), 128, buf);
  }

  if (result.empty()) {
    return std::nullopt;
  }
  return result;
}

void
TraceeCommandInterface::SetTarget(TraceeController *supervisor) noexcept
{
  ASSERT(tc == nullptr, "Target already configured with this interface!");
  tc = supervisor;
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