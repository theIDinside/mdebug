/** LICENSE TEMPLATE */
#include "stopreply_parser.h"
#include "connection.h"

namespace mdb::gdb {
StopReplyParser::StopReplyParser(const RemoteSettings &settings, std::string_view reply) noexcept
    : mReceivedPayload(reply), mParseData(reply), mMultiProcessConfigured(settings.mMultiProcessIsConfigured)
{
}

char
StopReplyParser::StopReplyKind() noexcept
{
  const auto ch = mParseData[0];
  mParseData.remove_prefix(1);
  return ch;
}

std::optional<int>
StopReplyParser::ParseSignal() noexcept
{
  if (mParseData.size() > 2) {
    constexpr auto SignalLengthInHexDigits = 2;
    auto signal = RemoteConnection::ParseHexDigits(mParseData.substr(0, SignalLengthInHexDigits));
    mParseData.remove_prefix(SignalLengthInHexDigits);
    return signal;
  }
  return {};
}

std::optional<int>
StopReplyParser::ParseExitCode() noexcept
{
  if (mParseData.size() > 2) {
    auto pos = mParseData.find(";");
    if (pos == mParseData.npos) {
      return {};
    }
    auto signal = RemoteConnection::ParseHexDigits(mParseData.substr(0, pos));
    mParseData.remove_prefix(pos);
    return signal;
  }
  return {};
}

std::optional<Pid>
StopReplyParser::ParseProcess() noexcept
{
  using namespace std::string_view_literals;
  static constexpr auto ProcessParameter = ";process:"sv;
  if (auto pos = mParseData.find(ProcessParameter); pos != std::string_view::npos) {
    mParseData.remove_prefix(pos + ProcessParameter.size());
    auto signal = RemoteConnection::ParseHexDigits(mParseData);
    mParseData = "";
    return signal;
  } else {
    return {};
  }
}

std::optional<std::tuple<Pid, Tid, int>>
StopReplyParser::ParseThreadExited() noexcept
{
  const auto exitStatus = ParseExitCode();
  if (!exitStatus) {
    DBGLOG(remote, "Failed to parse exit code for w packet: '{}'", mReceivedPayload);
  }

  if (mParseData.size() > 1 && mParseData[0] != ';') {
    DBGLOG(remote, "Invalid 'w' packet. A thread id must be found but wasn't in '{}'", mReceivedPayload);
    return {};
  }
  mParseData.remove_prefix(1);
  const auto [pid, tid] = gdb::GdbThread::parse_thread(mParseData);

  return std::make_tuple(pid, tid, exitStatus.value());
}
} // namespace mdb::gdb