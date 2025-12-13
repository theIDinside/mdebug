/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/typedefs.h>
#include <utils/logger.h>

// stdlib
#include <optional>
#include <string_view>

namespace mdb::gdb {
struct RemoteSettings;

struct StopReplyParser
{
  std::string_view mReceivedPayload;
  std::string_view mParseData;
  bool mMultiProcessConfigured;

public:
  StopReplyParser(const RemoteSettings &settings, std::string_view reply) noexcept;

  char StopReplyKind() noexcept;
  std::optional<int> ParseSignal() noexcept;
  std::optional<int> ParseExitCode() noexcept;
  std::optional<SessionId> ParseProcess() noexcept;
  std::optional<std::tuple<SessionId, Tid, int>> ParseThreadExited() noexcept;

  template <char Packet>
  std::pair<std::optional<SessionId>, std::optional<int>>
  ParseExited() noexcept
  {
    const auto signal = ParseExitCode();
    if (!signal) {
      DBGLOG(remote, "Failed to parse signal for {} packet: '{}'", Packet, mReceivedPayload);
    }
    const auto target = ParseProcess();
    if (mMultiProcessConfigured && !target) {
      DBGLOG(remote,
        "Failed to parse process for {} packet - we expect multiprocess extension to be turned on: '{}'",
        Packet,
        mReceivedPayload);
    }
    return std::make_pair(target, signal);
  }
};
} // namespace mdb::gdb