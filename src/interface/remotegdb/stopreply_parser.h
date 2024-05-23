#pragma once
#include "utils/logger.h"
#include <optional>
#include <string_view>
#include <typedefs.h>

namespace gdb {
struct RemoteSettings;

struct StopReplyParser
{
  std::string_view received_payload;
  std::string_view parse_data;
  bool mp_configured;

public:
  StopReplyParser(const RemoteSettings &settings, std::string_view reply) noexcept;

  char stop_reply_kind() noexcept;
  std::optional<int> parse_exitcode_or_signal() noexcept;
  std::optional<Pid> parse_process() noexcept;
  std::optional<std::pair<Tid, int>> parse_thread_exited() noexcept;

  template <char Packet>
  std::pair<std::optional<Pid>, std::optional<int>>
  parse_exited() noexcept
  {
    const auto signal = parse_exitcode_or_signal();
    if (!signal) {
      DLOG(logging::Channel::remote, "Failed to parse signal for {} packet: '{}'", Packet, received_payload);
    }
    const auto target = parse_process();
    if (mp_configured && !target) {
      DLOG(logging::Channel::remote,
           "Failed to parse process for {} packet - we expect multiprocess extension to be turned on: '{}'",
           Packet, received_payload);
    }
    return std::make_pair(target, signal);
  }
};
} // namespace gdb