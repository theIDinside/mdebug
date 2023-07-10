#include "events.h"
#include "nlohmann/json.hpp"

namespace ui::dap {

std::string
ProtocolMessage::header(const std::string &payload) noexcept
{
  return fmt::format("Content-Length: {}\r\n\r\n", payload.size());
}

ThreadEvent::ThreadEvent(ThreadReason reason, Tid tid) noexcept : reason(reason), tid(tid) {}

SerializedProtocolMessage
ThreadEvent::serialize(int seq) noexcept
{
  const auto payload = fmt::format(
      R"({{ "seq": {}, "type": "event", "event": "thread", "body": {{ "reason": "{}", "threadId": {} }} }})", seq,
      to_str(reason), tid);
  return SerializedProtocolMessage{header(payload), payload};
}

StoppedEvent::StoppedEvent(StoppedReason reason, std::string_view description, std::vector<int> bps) noexcept
    : reason(reason), description(description), bp_ids(bps)
{
}

SerializedProtocolMessage
StoppedEvent::serialize(int seq) noexcept
{
  PANIC("unimplemented");
}

SerializedProtocolMessage
BreakpointEvent::serialize(int seq) noexcept
{
  PANIC("unimplemented");
}

OutputEvent::OutputEvent(std::string_view category, std::string &&output) noexcept
    : category(category), output(std::move(output))
{
}

SerializedProtocolMessage
OutputEvent::serialize(int seq) noexcept
{
  nlohmann::json escape_hack;
  escape_hack = output;
  const auto body = escape_hack.dump();
  const auto payload = fmt::format(
      R"({{ "seq": {}, "type": "event", "event": "output", "body": {{ "category": "{}", "output": {} }} }})", seq,
      category, body);
  return SerializedProtocolMessage{header(payload), payload};
}
} // namespace ui::dap