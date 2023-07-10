#include "protocol.h"
#include "dap_defs.h"
#include "nlohmann/json_fwd.hpp"
using Dict = nlohmann::json;
namespace ui::dap {

Dict
event(std::string_view event)
{
  Dict dict;
  dict["type"] = "event";
  dict["event"] = event;
  dict["body"] = {};
  return dict;
}

Dict
request(std::string_view command)
{
  Dict dict;
  dict["type"] = "request";
  dict["command"] = command;
  dict["arguments"] = {};
  return dict;
}

Dict
response(int request_seq, bool success, std::string_view command, Option<std::string_view> err_message) noexcept
{
  Dict dict;
  dict["type"] = "response";
  dict["request_seq"] = request_seq;
  dict["success"] = success;
  dict["command"] = command;
  if (!success && err_message) {
    dict["message"] = *err_message;
  }
  dict["body"] = {};
  return dict;
}

Dict
stopped_event(StoppedReason reason, Option<std::string> description = {}, Option<int> threadId = {},
              Option<bool> preserveFocus = {}, Option<bool> allThreadsStopped = {},
              Option<std::vector<int>> hitBreakpointIds = {}) noexcept
{
  Dict dict = event("stopped");
  auto &body = dict["body"];
  body["reason"] = ui::dap::to_str(reason);
  if (description) {
    body["description"] = *description;
  }
  if (threadId) {
    body["threadId"] = *threadId;
  }
  if (preserveFocus) {
    body["preserveFocus"] = *preserveFocus;
  }
  if (allThreadsStopped) {
    body["allThreadsStopped"] = *allThreadsStopped;
  }
  if (hitBreakpointIds) {
    body["hitBreakpointIds"] = *hitBreakpointIds;
  }
  return dict;
}

Dict
thread_event(ThreadReason reason, int threadId) noexcept
{
  Dict dict = event("thread");
  auto &body = dict["body"];
  body["reason"] = to_str(reason);
  body["threadId"] = threadId;
  return dict;
}

Dict
continue_request(int threadId, bool singleThread = false) noexcept
{
  auto dict = request("continue");
  auto &args = dict["arguments"];
  args["threadId"] = threadId;
  args["singleThread"] = singleThread;
  return dict;
}
} // namespace ui::dap