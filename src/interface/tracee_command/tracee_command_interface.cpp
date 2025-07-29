/** LICENSE TEMPLATE */
#include "tracee_command_interface.h"
#include "common.h"
#include "interface/tracee_command/ptrace_commander.h"
#include <supervisor.h>
#include <tracer.h>
#include <type_traits>

namespace mdb::tc {

TraceeCommandInterface::TraceeCommandInterface(TargetFormat format,
                                               std::shared_ptr<gdb::ArchictectureInfo> &&arch_info,
                                               TraceeInterfaceType type) noexcept
    : mFormat(format), mArchInfo(std::move(arch_info)), mType(type)
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
TraceeCommandInterface::ReverseContinue(bool onlyStep) noexcept
{
  // In the future, when we're 100% certain that everything works as intended, we can change this
  // to just return a TaskExecuteResponse::Error. But for now, we want it to be a hard error, so that we catch when
  // the system has an invalid configuration
  PANIC("Something is broken if this ever gets called.");
  return TaskExecuteResponse::Error(0);
}

TaskExecuteResponse
TraceeCommandInterface::DoDisconnect(bool terminate) noexcept
{
  if (terminate) {
    Disconnect(true);
    return TaskExecuteResponse::Ok();
  }

  for (auto &user : mControl->GetUserBreakpoints().AllUserBreakpoints()) {
    mControl->GetUserBreakpoints().RemoveUserBreakpoint(user->mId);
  }
  Disconnect(false);

  return TaskExecuteResponse::Ok();
}

std::optional<std::string>
TraceeCommandInterface::ReadNullTerminatedString(TraceePointer<char> address) noexcept
{
  std::string result{};
  if (address == nullptr) {
    return std::nullopt;
  }
  u8 buf[256];
  auto res = ReadBytes(address.As<void>(), std::size(buf), buf);
  while (res.WasSuccessful()) {
    for (auto i = 0u; i < res.uBytesRead; ++i) {
      if (buf[i] == 0) {
        return result;
      }
      result.push_back(buf[i]);
    }
    res = ReadBytes(address.As<void>(), 128, buf);
  }

  if (result.empty()) {
    return std::nullopt;
  }
  return result;
}

void
TraceeCommandInterface::SetTarget(TraceeController *supervisor) noexcept
{
  ASSERT(mControl == nullptr, "Target already configured with this interface!");
  mControl = supervisor;
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
  case RunType::Unknown:
    return "RunType::UNKNOWN";
    break;
  }
  __builtin_unreachable();
}

} // namespace mdb::tc