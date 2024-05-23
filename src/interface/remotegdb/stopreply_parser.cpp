#include "stopreply_parser.h"
#include "connection.h"

namespace gdb {
StopReplyParser::StopReplyParser(const RemoteSettings &settings, std::string_view reply) noexcept
    : received_payload(reply), parse_data(reply), mp_configured(settings.multiprocess_configured)
{
}

char
StopReplyParser::stop_reply_kind() noexcept
{
  const auto ch = parse_data[0];
  parse_data.remove_prefix(1);
  return ch;
}

std::optional<int>
StopReplyParser::parse_exitcode_or_signal() noexcept
{
  if (parse_data.size() > 2) {
    auto signal = RemoteConnection::parse_hexdigits(parse_data.substr(0, 2));
    parse_data.remove_prefix(2);
    return signal;
  }
  return {};
}

std::optional<Pid>
StopReplyParser::parse_process() noexcept
{
  using namespace std::string_view_literals;
  static constexpr auto ProcessParameter = ";process:"sv;
  if (auto pos = parse_data.find(ProcessParameter); pos != std::string_view::npos) {
    parse_data.remove_prefix(pos + ProcessParameter.size());
    auto signal = RemoteConnection::parse_hexdigits(parse_data);
    parse_data = "";
    return signal;
  } else {
    return {};
  }
}

std::optional<std::pair<Tid, int>>
StopReplyParser::parse_thread_exited() noexcept
{
  const auto exit_status = parse_exitcode_or_signal();
  if (!exit_status) {
    DLOG(logging::Channel::remote, "Failed to parse exit code for w packet: '{}'", received_payload);
  }

  if (parse_data.size() > 1 && parse_data[0] != ';') {
    DLOG(logging::Channel::remote, "Invalid 'w' packet. A thread id must be found but wasn't in '{}'",
         received_payload);
    return {};
  }
  parse_data.remove_prefix(1);
  Tid tid{0};

  const auto res = std::from_chars(parse_data.data(), parse_data.data() + parse_data.size(), tid, 16);
  if (res.ec != std::errc()) {
    DLOG(logging::Channel::remote, "Invalid 'w' packet. Could not parse thread id from: '{}'", received_payload);
    return {};
  }
  return std::make_pair(tid, exit_status.value());
}
} // namespace gdb