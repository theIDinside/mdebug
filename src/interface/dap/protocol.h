#pragma once
#include "dap_defs.h"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

using Dict = nlohmann::json;

namespace ui::dap {

template <typename T> using Option = std::optional<T>;

Dict response(int request_seq, bool success, std::string_view command,
              Option<std::string_view> err_message) noexcept;

Dict stopped_event(StoppedReason reason, Option<std::string> description, Option<int> threadId,
                   Option<bool> preserveFocus, Option<bool> allThreadsStopped,
                   Option<std::vector<int>> hitBreakpointIds) noexcept;

Dict thread_event(ThreadReason reason, int threadId) noexcept;

/** Construct a serializable json dict for a continue request. `singleThread` defaults to false (all stop mode)*/
Dict continue_request(int threadId, bool singleThread) noexcept;

}; // namespace ui::dap